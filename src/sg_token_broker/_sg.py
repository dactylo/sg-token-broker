"""Mint SG session and REST tokens without `shotgun_api3`."""

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TypeAlias, cast

import requests

from sg_token_broker._urlpolicy import require_https_or_loopback

_ERROR_TITLE_MAX_CHARS = 120
# shotgun_api3's AuthenticationFault error_code: SG rejected the credentials/session.
_ERR_AUTH_CODE = 102
_REQUEST_TIMEOUT_SECONDS = 10.0
_REST_AUTH_PATH = '/api/v1.1/auth/access_token'
_RPC_PATH = '/api3/json'

_JSON: TypeAlias = 'bool | int | float | str | list[_JSON] | dict[str, _JSON] | None'


@dataclass(frozen=True)
class MintedToken:
    """Represent a token minted from SG.

    `expires_in` is None for session tokens (lifetime is governed by the SG
    site session preference, not reported per token).

    Attributes:
        token: Minted token credential.
        expires_in: SG-reported lifetime in seconds, or `None` for a session
            token.
    """

    token: str = field(repr=False)
    expires_in: int | None


class SGError(Exception):
    """An upstream SG call failed.

    Attributes:
        status_code: HTTP status of the upstream response, when one arrived
            (None for connection-level failures).
        error_code: SG JSON-RPC `error_code` when the RPC returned an exception
            body (102 for authentication failures).
        error_title: First error title from an SG REST error body, if any.
        rpc_message: Bounded message from an SG RPC fault, if any.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: int | None = None,
        error_title: str | None = None,
        rpc_message: str | None = None,
    ) -> None:
        """Attach upstream response details to an SG failure.

        Args:
            message: Human-readable failure description exposed through the
                exception's string form.
            status_code: HTTP status of the upstream response, when one arrived
                (`None` for connection-level failures).
            error_code: SG JSON-RPC `error_code` when the RPC returned an
                exception body (102 for authentication failures).
            error_title: First error title from an SG REST error body, if any.
            rpc_message: Bounded message from an SG RPC fault, if any.
        """
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.error_title = error_title
        self.rpc_message = rpc_message


class SGMinter:
    """Mint SG credentials using master script keys."""

    def __init__(
        self,
        site_url: str,
        *,
        timeout: float = _REQUEST_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        """Configure upstream SG requests and transport.

        Args:
            site_url: Base URL of the SG site.
            timeout: Per-request timeout in seconds. Defaults to `10.0`.
            session: Optional preconfigured Requests session. Defaults to a new
                session.

        Raises:
            SGError: If `site_url` is malformed, unsupported, or insecure.
        """
        try:
            self._site_url = require_https_or_loopback(site_url, 'SG site URL').rstrip('/')
        except ValueError as exc:
            raise SGError(str(exc)) from exc
        self._timeout = timeout
        self._session = session if session is not None else requests.Session()

    def _post_json(
        self,
        path: str,
        *,
        json_body: dict[str, _JSON] | None = None,
        form: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Post to the SG site and return the decoded JSON object."""
        url = f'{self._site_url}{path}'
        try:
            response = self._session.post(
                url,
                allow_redirects=False,
                json=json_body,
                data=form,
                timeout=self._timeout,
                headers={'Accept': 'application/json'},
            )
        except requests.RequestException as exc:
            raise SGError(f'SG request to {path} failed: {exc.__class__.__name__}') from exc
        if response.status_code != HTTPStatus.OK:
            message = f'SG request to {path} returned HTTP {response.status_code}'
            title = _extract_error_title(response)
            if title is not None:
                message = f'{message}: {title}'
            raise SGError(message, status_code=response.status_code, error_title=title)
        try:
            data: object = response.json()
        except ValueError as exc:
            raise SGError(f'SG response from {path} was not JSON') from exc
        if not isinstance(data, dict):
            raise SGError(f'SG response from {path} was not a JSON object')
        return cast('dict[str, object]', data)

    def check_session_token(self, session_token: str) -> bool:
        """Return True if SG still accepts the session token.

        Calls the `get_session_token` RPC authenticated by the session token
        itself (with `reject_if_expired`), which needs no entity permissions
        and works regardless of the scope's permission rule set.

        Args:
            session_token: The session token to probe.

        Returns:
            True if the session is alive, False if SG rejected it as an
            authentication failure (error_code 102).

        Raises:
            SGError: If the SG site is unreachable or the response was neither
                a clean acceptance nor an authentication rejection (transport
                failure, non-200, malformed body, or another SG fault) - all
                distinct from revocation.
        """
        payload: dict[str, _JSON] = {
            'method_name': 'get_session_token',
            'params': [{'session_token': session_token, 'reject_if_expired': True}],
        }
        data = self._post_json(_RPC_PATH, json_body=payload)
        if data.get('exception'):
            error_code = data.get('error_code')
            if type(error_code) is int and error_code == _ERR_AUTH_CODE:
                return False
            message = _bounded_message(data)
            raise SGError(f'SG session probe failed: {message}', rpc_message=message)
        if _extract_session_id(data) is None:
            raise SGError('SG session probe response contained no session_id')
        return True

    def mint_rest_token(
        self, script_name: str, script_key: str, *, scope: str | None = None
    ) -> MintedToken:
        """Mint a REST API access token via the client_credentials grant.

        The refresh token returned by SG is intentionally discarded.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser script key.
            scope: Optional SG token scope (e.g. `sudo_as_login:<login>`);
                the binding is fixed by SG at mint time.

        Returns:
            The minted access token with its SG-reported lifetime.

        Raises:
            SGError: If the SG site is unreachable, rejects the request, or
                returns a malformed token response.
        """
        form = {
            'grant_type': 'client_credentials',
            'client_id': script_name,
            'client_secret': script_key,
        }
        if scope is not None:
            form['scope'] = scope
        data = self._post_json(_REST_AUTH_PATH, form=form)
        token = data.get('access_token')
        expires_in = data.get('expires_in')
        if not isinstance(token, str) or type(expires_in) is not int:
            raise SGError('SG response did not contain access_token/expires_in')
        return MintedToken(token=token, expires_in=expires_in)

    def mint_session_token(
        self, script_name: str, script_key: str, *, sudo_login: str | None = None
    ) -> MintedToken:
        """Mint an SG session token for the given script credentials.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser script key.
            sudo_login: Optional HumanUser login; when set, SG binds the
                session to that user at mint time (`sudo_as_login`).

        Returns:
            The minted session token with `expires_in` set to `None`.

        Raises:
            SGError: If the SG site is unreachable, rejects the request, or
                returns a malformed token response. RPC rejections carry
                `error_code`.
        """
        params: dict[str, _JSON] = {'script_name': script_name, 'script_key': script_key}
        if sudo_login is not None:
            params['sudo_as_login'] = sudo_login
        payload: dict[str, _JSON] = {'method_name': 'get_session_token', 'params': [params]}
        data = self._post_json(_RPC_PATH, json_body=payload)
        if data.get('exception'):
            message = _bounded_message(data)
            raw_code = data.get('error_code')
            code = raw_code if type(raw_code) is int else None
            raise SGError(
                f'SG rejected session token request: {message}',
                error_code=code,
                rpc_message=message,
            )
        session_id = _extract_session_id(data)
        if session_id is None:
            raise SGError('SG response did not contain a session_id')
        return MintedToken(token=session_id, expires_in=None)


def _bounded_message(data: dict[str, object]) -> str:
    """Return the RPC error message as a capped string, or a fixed fallback."""
    message = data.get('message')
    if isinstance(message, str) and message:
        return message[:_ERROR_TITLE_MAX_CHARS]
    return 'unknown error'


def _extract_error_title(response: requests.Response) -> str | None:
    """Pull the first non-empty error title out of an SG error body, if any."""
    try:
        data: object = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    errors = cast('dict[str, object]', data).get('errors')
    if not isinstance(errors, list):
        return None
    for entry in cast('list[object]', errors):
        if isinstance(entry, dict):
            title = cast('dict[str, object]', entry).get('title')
            if isinstance(title, str) and title:
                return title[:_ERROR_TITLE_MAX_CHARS]
    return None


def _extract_session_id(data: dict[str, object]) -> str | None:
    """Return the session ID from a supported response shape."""
    session_id = data.get('session_id')
    if isinstance(session_id, str) and session_id.strip():
        return session_id
    results = data.get('results')
    if isinstance(results, dict):
        nested = cast('dict[str, object]', results).get('session_id')
        if isinstance(nested, str) and nested.strip():
            return nested
    return None
