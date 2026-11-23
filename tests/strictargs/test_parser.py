import argparse
import sys
from functools import partial
from typing import Never

import pytest

from sg_token_broker._vendor.strictargs import (
    StrictParser,
)


def test_abbreviation_setting_is_fixed() -> None:
    with pytest.raises(TypeError, match='allow_abbrev'):
        StrictParser(allow_abbrev=True)


def test_callable_subparser_factory_accepts_child_options() -> None:
    parser = StrictParser(prog='tool')
    action_type = type(argparse.ArgumentParser().add_subparsers())
    parser.register('action', 'parsers', partial(action_type))
    parser.add_subparsers().add_parser('run').add_argument('--scope')
    assert parser.parse_known_args(['run', '--scope=x']) == (argparse.Namespace(scope='x'), [])


def test_delimiter_and_ordinary_leftovers(capsys: pytest.CaptureFixture[str]) -> None:
    parser = StrictParser()
    parser.add_argument('operand')
    parser.add_argument('--write', action='store_true')
    argv = ['one', '--', '--wri', 'two']
    namespace, remaining = parser.parse_known_args(argv)
    assert namespace.operand == 'one'
    assert remaining == ['--wri', 'two']
    with pytest.raises(SystemExit):
        parser.parse_args(argv)
    assert capsys.readouterr().err.endswith('unrecognized arguments: --wri two\n')
    with pytest.raises(SystemExit):
        parser.parse_known_args(['--wri', *argv])
    assert capsys.readouterr().err.endswith(
        'unrecognized arguments: --wri (did you mean --write?)\n'
    )


def test_name_suggestions_are_enabled_unless_disabled() -> None:
    if sys.version_info < (3, 14):
        pytest.skip('argparse added name suggestions in 3.14')
    assert StrictParser().suggest_on_error
    assert not StrictParser(suggest_on_error=False).suggest_on_error


def test_parent_failure_before_subcommand_selection_keeps_argparse_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = StrictParser(prog='tool')
    root.add_argument('--count', type=int)
    root.add_subparsers().add_parser('read')
    with pytest.raises(SystemExit) as error:
        root.parse_args(['--coun', '--count', 'bad', 'read'])
    assert error.value.code == 2
    diagnostic = capsys.readouterr().err.splitlines()[-1]
    assert '--count' in diagnostic
    assert 'bad' in diagnostic


def test_parent_reports_unknown_leftover_without_a_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = StrictParser(prog='tool')
    root.add_argument('--scope')
    root.add_subparsers().add_parser('read')
    _, tail = root.parse_known_args(['read', '--', '--scop'])
    assert tail == ['--', '--scop']
    with pytest.raises(SystemExit) as error:
        root.parse_known_args(['--scop'])
    assert error.value.code == 2
    assert capsys.readouterr().err.endswith(
        'tool: error: unrecognized arguments: --scop (did you mean --scope?)\n'
    )


def test_parent_required_option_error_precedes_leftover_typo(
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = StrictParser(prog='tool')
    root.add_argument('--scope', required=True)
    root.add_subparsers().add_parser('read')
    with pytest.raises(SystemExit) as error:
        root.parse_args(['--scop', 'read'])
    assert error.value.code == 2
    assert capsys.readouterr().err.endswith('the following arguments are required: --scope\n')


def test_regular_parser_arity_does_not_hide_subcommands() -> None:
    root = StrictParser()
    root.add_argument('--forward', nargs=argparse.PARSER)
    child = root.add_subparsers().add_parser('read')
    child.add_argument('--scope')
    assert root.parse_args(['read', '--scope=x']).scope == 'x'


def test_regular_parser_arity_keeps_leaf_typo_precedence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = StrictParser()
    parser.add_argument('--forward', nargs=argparse.PARSER, choices=['read'])
    parser.add_argument('--scope', required=True)
    with pytest.raises(SystemExit) as error:
        parser.parse_args(['--forward', 'read', '--scop'])
    assert error.value.code == 2
    assert capsys.readouterr().err.endswith(
        'unrecognized arguments: --scop (did you mean --scope?)\n'
    )


@pytest.mark.parametrize(
    ('settings', 'option'),
    [
        ({'exit_on_error': False}, 'exit_on_error'),
        ({'fromfile_prefix_chars': '@'}, 'fromfile_prefix_chars'),
    ],
)
def test_settings_that_bypass_usage_errors_are_rejected(
    settings: dict[str, object], option: str
) -> None:
    with pytest.raises(TypeError, match=rf'{option}.*error'):
        StrictParser(**settings)


@pytest.mark.parametrize('method', ['parse_args', 'parse_known_args'])
def test_diagnostic_lists_only_unknown_long_options_in_order(
    method: str, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = StrictParser(prog='tool')
    parser.add_argument('--ca-bundle')
    parser.add_argument('--scope')
    argv = ['-z', '--ca', 'x', '--scope=valid', '--scoep=value', '--qqqq', 'tail']
    parse = parser.parse_args if method == 'parse_args' else parser.parse_known_args
    with pytest.raises(SystemExit) as error:
        parse(iter(argv))
    assert error.value.code == 2
    assert capsys.readouterr().err.splitlines()[-1] == (
        'tool: error: unrecognized arguments: --ca (did you mean --ca-bundle?) '
        '--scoep=value (did you mean --scope?) --qqqq'
    )


@pytest.mark.parametrize('kind', ['leaf', 'parent'])
def test_override_can_replace_all_diagnostic_text(
    kind: str, capsys: pytest.CaptureFixture[str]
) -> None:
    messages: list[str] = []

    class Parser(StrictParser):
        def error(self, message: str) -> Never:
            messages.append(message)
            super().error('invalid input')

    parser = Parser(prog='tool')
    parser.add_argument('--scope', required=kind == 'leaf')
    if kind == 'parent':
        parser.add_subparsers().add_parser('read')
    with pytest.raises(SystemExit) as error:
        parser.parse_known_args(['--scop=sensitive'])
    assert messages == ['unrecognized arguments: --scop=sensitive (did you mean --scope?)']
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == parser.format_usage() + 'tool: error: invalid input\n'


@pytest.mark.parametrize('option', ['--help', '--version'])
def test_leaf_typo_precedes_help_and_version(
    option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = StrictParser()
    parser.add_argument('--version', action='version', version='1')
    parser.add_argument('--scope')
    with pytest.raises(SystemExit) as error:
        parser.parse_args([option, '--scop'])
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err.endswith('unrecognized arguments: --scop (did you mean --scope?)\n')


def test_subcommand_reports_its_usage_and_options(capsys: pytest.CaptureFixture[str]) -> None:
    root = StrictParser(prog='tool')
    root.add_argument('--cache')
    child = root.add_subparsers().add_parser('get-token')
    child.add_argument('--ca-bundle', required=True)
    with pytest.raises(SystemExit) as error:
        root.parse_args(['get-token', '--ca', 'x'])
    assert error.value.code == 2
    lines = capsys.readouterr().err.splitlines()
    assert lines[0].startswith('usage: tool get-token ')
    assert lines[-1] == (
        'tool get-token: error: unrecognized arguments: --ca (did you mean --ca-bundle?)'
    )


def test_two_completions_and_hidden_spelling(capsys: pytest.CaptureFixture[str]) -> None:
    parser = StrictParser()
    parser.add_argument('--cache')
    parser.add_argument('--ca-bundle')
    parser.add_argument('--hidden', help=argparse.SUPPRESS)
    assert parser.parse_args(['--hidden=ok']).hidden == 'ok'
    with pytest.raises(SystemExit):
        parser.parse_args(['--ca', '--hidde'])
    assert capsys.readouterr().err.endswith(
        'unrecognized arguments: --ca (did you mean --ca-bundle or --cache?) --hidde\n'
    )
    parser.add_argument('--catalog')
    with pytest.raises(SystemExit):
        parser.parse_known_args(['--ca'])
    assert capsys.readouterr().err.endswith(
        'unrecognized arguments: --ca (did you mean --ca-bundle, --cache or --catalog?)\n'
    )


def test_typo_precedes_missing_required_option(capsys: pytest.CaptureFixture[str]) -> None:
    parser = StrictParser(prog='tool')
    parser.add_argument('--scope', required=True)
    with pytest.raises(SystemExit) as error:
        parser.parse_args(['--scop', 'x'])
    assert error.value.code == 2
    assert capsys.readouterr().err.endswith(
        'tool: error: unrecognized arguments: --scop (did you mean --scope?)\n'
    )
