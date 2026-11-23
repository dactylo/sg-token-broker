"""Report misspelled long options from the parser that owns the arguments."""

import argparse
import sys
from collections.abc import Callable, Iterable
from difflib import get_close_matches
from typing import TypeVar, cast, overload

_Namespace = TypeVar('_Namespace')


class StrictParser(argparse.ArgumentParser):
    """Require full long options and suggest corrections through `error`.

    A leaf rejects unknown long options before the first bare `--`, even beside
    help or version. A parent lets argparse parse first. It rejects unknown
    long options among the leftovers if their spelling appeared before the
    first bare `--` in its own input. Earlier argparse and child errors stand.
    Override `error` to replace a usage diagnostic.

    Usage errors require `exit_on_error=True` and disabled argument files
    (`fromfile_prefix_chars=None`). On Python 3.13 and later argparse emits
    deprecation warnings separately. Those warnings name registered options and
    do not include typed values.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Configure argparse with full option names and available choice hints.

        Args:
            *args: Positional ArgumentParser settings.
            **kwargs: ArgumentParser settings. On Python 3.14 and later, choice
                and subcommand suggestions default to enabled.

        Raises:
            TypeError: If a caller supplies `allow_abbrev`, disables error
                exits, or enables argument files.
        """
        if sys.version_info >= (3, 14):
            kwargs.setdefault('suggest_on_error', True)
        # argparse owns the version-specific constructor and validates forwarded arguments.
        initialize: Callable[..., None] = super().__init__
        initialize(*args, allow_abbrev=False, **kwargs)
        # A caller can later replace this registry entry with an action factory.
        self._strictargs_subparser_type: type[argparse.Action] = self._registry_get(
            'action', 'parsers'
        )
        if not self.exit_on_error:
            raise TypeError('exit_on_error=False bypasses the usage error handler')
        if self.fromfile_prefix_chars is not None:
            raise TypeError(
                'fromfile_prefix_chars must be None because file errors bypass option checks'
            )

    def _annotate_option(self, token: str) -> str:
        """Append a correction for a visible long option when one matches."""
        name = token.partition('=')[0][2:]
        visible = [
            option[2:]
            for option, action in self._option_string_actions.items()
            if option.startswith('--') and action.help != argparse.SUPPRESS
        ]
        matches = sorted(option for option in visible if option.startswith(name))
        if not matches:
            matches = get_close_matches(name, visible, n=1)
        if not matches:
            return token
        choices = ['--' + match for match in matches]
        hint = choices[-1]
        if len(choices) > 1:
            hint = ', '.join(choices[:-1]) + ' or ' + hint
        return f'{token} (did you mean {hint}?)'

    def _is_unknown_option(self, token: str) -> bool:
        """Identify a long option whose name is absent from this parser."""
        return (
            token.startswith('--') and token.partition('=')[0] not in self._option_string_actions
        )

    def _check_options(self, arguments: Iterable[str]) -> None:
        """Report unknown long options in their input order."""
        hints = [self._annotate_option(arg) for arg in arguments if self._is_unknown_option(arg)]
        if hints:
            self.error('unrecognized arguments: ' + ' '.join(hints))

    @overload
    def parse_known_args(
        self, args: Iterable[str] | None = None, namespace: None = None
    ) -> tuple[argparse.Namespace, list[str]]: ...

    @overload
    def parse_known_args(
        self, args: Iterable[str] | None, namespace: _Namespace
    ) -> tuple[_Namespace, list[str]]: ...

    @overload
    def parse_known_args(self, *, namespace: _Namespace) -> tuple[_Namespace, list[str]]: ...

    def parse_known_args(
        self, args: Iterable[str] | None = None, namespace: _Namespace | None = None
    ) -> tuple[argparse.Namespace | _Namespace, list[str]]:
        """Parse known arguments and reject unknown long options before `--`.

        Args:
            args: Argument tokens, or process arguments when omitted.
            namespace: Existing namespace to fill when supplied.

        Returns:
            The populated namespace and remaining arguments in argparse order.

        Raises:
            SystemExit: After help or a usage error with the default handlers.
        """
        tokens = sys.argv[1:] if args is None else list(args)
        prefix = tokens[: tokens.index('--')] if '--' in tokens else tokens
        has_subcommands = any(
            isinstance(action, self._strictargs_subparser_type) for action in self._actions
        )
        if not has_subcommands:
            self._check_options(prefix)
        parsed, extras = super().parse_known_args(tokens, namespace)
        if has_subcommands and extras:
            eligible = set(prefix)
            self._check_options(arg for arg in extras if arg in eligible)
        return cast('argparse.Namespace | _Namespace', parsed), extras
