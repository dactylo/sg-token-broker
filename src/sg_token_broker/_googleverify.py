"""Google ID-token verification through the optional `google` extra."""

import importlib
from collections.abc import Mapping
from typing import cast

import requests

from sg_token_broker._gclaims import Verifier


class VerifierUnavailableError(Exception):
    """The Google verification dependency group is incomplete."""


def google_auth_verifier() -> Verifier:
    """Build a Verifier backed by google-auth ID-token verification.

    The returned callable wraps `verify_oauth2_token`: signature (against
    Google's published certs), expiry, and the `iss` claim are all checked.
    The audience stays unchecked here (`audience=None`); `_gclaims` validates
    `aud` against the configured list. google-auth raises ValueError for
    malformed/invalid tokens and GoogleAuthError for issuer failures; the
    latter is re-raised as ValueError to satisfy the `Verifier` contract.
    TransportError (a GoogleAuthError subclass raised when fetching Google's
    certs fails) deliberately propagates unwrapped so the HTTP layer reports it
    as a 500, not a caller auth failure.

    Returns:
        A `Verifier` suitable for `ClaimsValidator`.

    Raises:
        VerifierUnavailableError: If the Google verification dependencies are
            incomplete.
    """
    try:
        cachecontrol = importlib.import_module('cachecontrol')
        cache = importlib.import_module('cachecontrol.cache')
        exceptions = importlib.import_module('google.auth.exceptions')
        transport = importlib.import_module('google.auth.transport.requests')
        id_token = importlib.import_module('google.oauth2.id_token')
    except ImportError as exc:
        raise VerifierUnavailableError(
            'Google verification dependencies are incomplete; install the [google] extra'
        ) from exc
    session = requests.Session()
    cached_session = cachecontrol.CacheControl(session, cache=cache.DictCache())
    request = transport.Request(session=cached_session)

    def verify(presented: str) -> Mapping[str, object]:
        try:
            return cast(
                'Mapping[str, object]',
                id_token.verify_oauth2_token(presented, request, clock_skew_in_seconds=10),
            )
        except exceptions.TransportError:
            raise
        except exceptions.GoogleAuthError as exc:
            raise ValueError(str(exc)) from exc

    return verify
