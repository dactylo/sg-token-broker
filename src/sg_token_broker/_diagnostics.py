"""Compose provider diagnostics from local facts and recognized OAuth codes."""

import os
from typing import cast

import requests

_OAUTH_HINTS = {
    'access_denied': 'authorize the application to sign in',
    'invalid_client': 'check the configured OAuth client ID and secret',
    'invalid_grant': 'sign in again to obtain a fresh grant',
    'invalid_request': 'check the OAuth client configuration',
    'invalid_scope': 'check the scopes allowed for this client',
    'server_error': 'check the identity provider',
    'temporarily_unavailable': 'try the identity provider again later',
    'unauthorized_client': 'enable this grant for the OAuth client',
    'unsupported_grant_type': 'check the grant types enabled by the provider',
    'unsupported_response_type': 'enable the authorization code flow',
}


def local_send_detail(error: OSError, verify: object) -> str:
    """Describe a local send failure without including arbitrary exception text.

    Args:
        error: Operating-system or Requests send failure.
        verify: Session verification setting to check alongside CA-bundle
            environment settings.

    Returns:
        The known invalid-CA-path diagnostic on an exact match, otherwise the
        error type.
    """
    prefix = 'Could not find a suitable TLS CA certificate bundle, invalid path: '
    for path in (verify, os.environ.get('REQUESTS_CA_BUNDLE'), os.environ.get('CURL_CA_BUNDLE')):
        if isinstance(path, str) and str(error) == prefix + path:
            return prefix + path
    return type(error).__name__


def oauth_detail(code: object, *, missing_secret: bool = False) -> str:
    """Build a safe OAuth diagnostic suffix from a recognized error code.

    Args:
        code: Provider error code to match against locally defined hints.
        missing_secret: Add client-secret guidance for applicable client or
            request errors.

    Returns:
        A colon-prefixed diagnostic, or an empty string for an unknown code.
    """
    if not isinstance(code, str) or code not in _OAUTH_HINTS:
        return ''
    hint = _OAUTH_HINTS[code]
    if missing_secret and code in {'invalid_request', 'invalid_client'}:
        hint += '; if the client requires a secret, set SG_USER_TOKEN_CLIENT_SECRET'
    return f': {code}: {hint}'


def oauth_response_detail(response: requests.Response, *, missing_secret: bool = False) -> str:
    """Build a safe OAuth diagnostic suffix from the response's error field.

    Args:
        response: Provider response to inspect without retaining its
            descriptive text.
        missing_secret: Include client-secret guidance for applicable
            recognized errors.

    Returns:
        A locally composed suffix, or an empty string if no recognized code is
        available.
    """
    try:
        body: object = response.json()
    except ValueError:
        return ''
    if not isinstance(body, dict):
        return ''
    return oauth_detail(
        cast('dict[str, object]', body).get('error'), missing_secret=missing_secret
    )
