"""Mint SG session and REST tokens without `shotgun_api3`."""

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Literal, TypeAlias, cast

import requests

from sg_token_broker._diagnostics import local_send_detail
from sg_token_broker._urlpolicy import require_https_or_loopback

_RPC_HINTS = {
    100: 'SG reported a server fault',
    102: 'check the SG script name and key',
    106: 'SG requires two-factor authentication',
    108: 'SG requires single sign-on',
    110: 'SG requires Autodesk Identity authentication',
}
# shotgun_api3's AuthenticationFault error_code: SG rejected the credentials/session.
_ERR_AUTH_CODE = 102
_REQUEST_TIMEOUT_SECONDS = 10.0
_REST_AUTH_PATH = '/api/v1.1/auth/access_token'
_RPC_PATH = '/api3/json'
_TARGET_REFUSAL_MARKERS = ("cannot 'sudo'", 'cannot sudo as')

SGFailureKind: TypeAlias = Literal['rejected', 'invalid_response', 'unavailable']
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
        audit_detail: Operation and failure description without upstream text.
        status_code: Recorded upstream HTTP status, or `None` if the failure
            carries no status.
        target_refused: Whether SG specifically denied minting for the target
            user.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: int | None = None,
        target_refused: bool = False,
    ) -> None:
        """Attach upstream response details to an SG failure.

        Args:
            message: Locally composed failure description suitable for audit
                logs.
            status_code: Recorded upstream HTTP status, or `None` if the
                failure carries no status.
            error_code: Recognized SG JSON-RPC fault code, or `None` when
                absent or unrecognized.
            target_refused: Whether SG specifically denied the target user.
        """
        super().__init__(message)
        self.audit_detail = message
        self.target_refused = target_refused
        self.status_code = status_code
        self._error_code = error_code

    @property
    def rejected_credentials(self) -> bool:
        """Return whether SG explicitly refused the submitted authentication."""
        return self.status_code == HTTPStatus.UNAUTHORIZED or (
            self.status_code == HTTPStatus.OK and self._error_code == _ERR_AUTH_CODE
        )


class SGInvalidResponseError(SGError):
    """SG returned a successful response without usable data."""


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
            self._site_url = require_https_or_loopback(
                site_url, 'SG site URL', credential_settings='the SG script name and key settings'
            ).rstrip('/')
        except ValueError as exc:
            raise SGError(str(exc)) from exc
        self._timeout = timeout
        self._session = session if session is not None else requests.Session()

    def _post_json(
        self,
        path: str,
        operation: str,
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
        except (requests.RequestException, ValueError) as exc:
            raise SGError(f'SG request to {path} failed: {exc.__class__.__name__}') from None
        except OSError as exc:
            detail = local_send_detail(exc, self._session.verify)
            raise SGError(f'SG request to {path} could not be sent: {detail}') from None
        if response.status_code != HTTPStatus.OK:
            message = f'{operation} returned HTTP {response.status_code}'
            if classify_sg_status(response.status_code) == 'invalid_response':
                raise SGInvalidResponseError(message, status_code=response.status_code)
            if operation == 'SG session probe':
                raise SGError(message, status_code=response.status_code)
            raise _refusal_error(
                message, response.status_code, None, _extract_error_title(response)
            )
        try:
            data: object = response.json()
        except ValueError:
            raise SGInvalidResponseError(f'SG response from {path} was not JSON') from None
        if not isinstance(data, dict):
            raise SGInvalidResponseError(f'SG response from {path} was not a JSON object')
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
        data = self._post_json(_RPC_PATH, 'SG session probe', json_body=payload)
        if data.get('exception'):
            error_code = data.get('error_code')
            if type(error_code) is int and error_code == _ERR_AUTH_CODE:
                return False
            raise _rpc_failure('SG session probe failed', data)
        if _extract_session_id(data) is None:
            raise SGInvalidResponseError('SG session probe response contained no session_id')
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
        data = self._post_json(_REST_AUTH_PATH, 'SG REST token request', form=form)
        token = data.get('access_token')
        expires_in = data.get('expires_in')
        if not isinstance(token, str) or not token.strip() or type(expires_in) is not int:
            raise SGInvalidResponseError('SG response did not contain access_token/expires_in')
        if expires_in <= 0:
            raise SGInvalidResponseError('SG response expires_in must be positive')
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
                returns a malformed token response.
        """
        params: dict[str, _JSON] = {'script_name': script_name, 'script_key': script_key}
        if sudo_login is not None:
            params['sudo_as_login'] = sudo_login
        payload: dict[str, _JSON] = {'method_name': 'get_session_token', 'params': [params]}
        data = self._post_json(_RPC_PATH, 'SG session token request', json_body=payload)
        if data.get('exception'):
            raise _rpc_failure('SG rejected session token request', data)
        session_id = _extract_session_id(data)
        if session_id is None:
            raise SGInvalidResponseError('SG response did not contain a session_id')
        return MintedToken(token=session_id, expires_in=None)


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
                return title
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


def _refusal_error(operation: str, status: int, code: int | None, text: object) -> SGError:
    """Classify a refusal in memory and retain only local facts."""
    hint = _RPC_HINTS.get(code, '') if code is not None else ''
    target = False
    if status in {HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED} or code == _ERR_AUTH_CODE:
        reason = text.lower() if isinstance(text, str) else ''
        if "does not have permission to 'sudo'" in reason:
            hint = 'grant the script permission to act for users'
        elif "can't authenticate script" in reason:
            hint = _RPC_HINTS[_ERR_AUTH_CODE]
        elif any(marker in reason for marker in _TARGET_REFUSAL_MARKERS):
            target = True
            hint = (
                'activate the target SG user'
                if 'inactive user account' in reason
                else 'check the target SG user'
            )
        elif status == HTTPStatus.UNAUTHORIZED:
            hint = _RPC_HINTS[_ERR_AUTH_CODE]
    message = f'{operation}: {hint}' if hint else operation
    return SGError(message, status_code=status, error_code=code, target_refused=target)


def _rpc_failure(operation: str, data: dict[str, object]) -> SGError:
    """Describe an RPC fault using recognized protocol codes."""
    raw = data.get('error_code')
    code = raw if type(raw) is int and raw in _RPC_HINTS else None
    codes = 'HTTP 200' if code is None else f'HTTP 200, RPC {code}'
    return _refusal_error(f'{operation} ({codes})', HTTPStatus.OK, code, data.get('message'))


def classify_sg_status(status_code: int) -> SGFailureKind:
    """Classify an unexpected HTTP status from an SG endpoint that requires 200."""
    if HTTPStatus.OK < status_code < HTTPStatus.MULTIPLE_CHOICES:
        return 'invalid_response'
    if (
        status_code == HTTPStatus.TOO_MANY_REQUESTS
        or status_code >= HTTPStatus.INTERNAL_SERVER_ERROR
    ):
        return 'unavailable'
    return 'rejected'


def classify_sg_failure(exc: SGError) -> SGFailureKind:
    """Classify a failed SG request for the token services."""
    if isinstance(exc, SGInvalidResponseError):
        return 'invalid_response'
    if exc.status_code is None:
        return 'unavailable'
    return classify_sg_status(exc.status_code)
