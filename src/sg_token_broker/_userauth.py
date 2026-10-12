"""Interactive OIDC sign-in for desktop tools: PKCE in the system browser."""

# pyright: reportPrivateUsage=false

import base64
import hashlib
import json
import os
import secrets
import socket
import sys
import threading
import webbrowser
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import cast
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import requests

from sg_token_broker._credstore import load_account, load_refresh_token, store_refresh_token
from sg_token_broker._urlpolicy import require_https_or_loopback

_BROWSER_RESPONSE = b'Sign-in complete. You can close this tab.'
_CALLBACK_PATH = '/callback'
_GOOGLE_AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
_GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'  # noqa: S105 - endpoint URL, not a credential
_JOIN_TIMEOUT_SECONDS = 2.0
_JWT_PART_COUNT = 3
_REQUEST_TIMEOUT_SECONDS = 10.0
_SCOPES = 'openid email'
_SIGN_IN_TIMEOUT_SECONDS = 180.0
_SUCCESS_STATUS = 200
_WINDOWS_NOT_SOCKET_ERROR = 10038


class SignInError(Exception):
    """The interactive sign-in failed or was rejected."""


class SignInSettingsError(SignInError):
    """The sign-in settings in the environment are missing or invalid."""


@dataclass(frozen=True)
class TokenBundle:
    """Represent the credentials produced by one interactive sign-in.

    Attributes:
        id_token: Provider ID token.
        refresh_token: Optional provider refresh credential. Defaults to
            `None`.
    """

    id_token: str = field(repr=False)
    refresh_token: str | None = field(repr=False, default=None)


class _CallbackServer(HTTPServer):
    """One-shot loopback HTTP server capturing the authorization response."""

    def __init__(self, *, join_timeout: float = _JOIN_TIMEOUT_SECONDS) -> None:
        """Bind a loopback callback listener and start its serving thread."""
        self._active_request: socket.socket | None = None
        self._closing = False
        self._request_lock = threading.Lock()
        self._code: str | None = None
        self._error: str | None = None
        self._error_description: str | None = None
        self._join_timeout = join_timeout
        self._state: str | None = None
        self._received = threading.Event()
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            """Handle callback requests for the enclosing one-shot server."""

            timeout = _REQUEST_TIMEOUT_SECONDS

            def _reject(self, status: int, reason: bytes) -> None:
                """Send one plain-text HTTP rejection."""
                self.send_response(status)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(reason)))
                self.end_headers()
                self.wfile.write(reason)

            def do_GET(self) -> None:
                """Capture an authorization callback or reject an invalid request."""
                try:
                    parts = urlsplit(self.path)
                except ValueError:
                    self._reject(400, b'malformed request target')
                    return
                if parts.path != _CALLBACK_PATH:
                    self._reject(404, b'not found')
                    return
                params = parse_qs(parts.query)
                outer._code = params.get('code', [None])[0]
                outer._error = params.get('error', [None])[0]
                outer._error_description = params.get('error_description', [None])[0]
                outer._state = params.get('state', [None])[0]
                try:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.send_header('Content-Length', str(len(_BROWSER_RESPONSE)))
                    self.end_headers()
                    self.wfile.write(_BROWSER_RESPONSE)
                finally:
                    outer._received.set()

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Suppress the base handler's access-log output."""
                del args, kwargs

        super().__init__(('127.0.0.1', 0), _Handler)
        port = self.server_address[1]
        self._address = ('127.0.0.1', port)
        self._redirect_uri = f'http://127.0.0.1:{port}{_CALLBACK_PATH}'
        self._thread = threading.Thread(target=self._serve_until_callback, daemon=True)
        self._thread.start()

    def __call__(
        self,
        authorization_url: str,
        open_browser: Callable[[str], object],
        timeout: float,
    ) -> None:
        """Launch sign-in and wait for exactly one browser callback."""
        try:
            browser_opened = open_browser(authorization_url)
        except BaseException as exc:
            self._close()
            if not isinstance(exc, Exception):
                raise
            raise SignInError(f'browser launch failed: {exc.__class__.__name__}') from exc
        if not browser_opened:
            self._close()
            raise SignInError('browser launch was rejected')
        self._wait(timeout)

    @staticmethod
    def _close_socket(request: socket.socket) -> None:
        """Shut down and close one accepted socket."""
        with suppress(OSError):
            request.shutdown(socket.SHUT_RDWR)
        if sys.platform == 'win32':
            # Buffered readers defer close; transfer ownership before native disposal
            # so their eventual close cannot affect a reused descriptor.
            descriptor = request.detach()
            if descriptor != -1:
                socket.close(descriptor)
        request.close()

    def _begin_close(self) -> None:
        """Mark closing and interrupt the active request, if any."""
        with self._request_lock:
            self._closing = True
            request = self._active_request
        if request is not None:
            self._close_socket(request)

    def _close(self) -> None:
        """Close the pending callback listener."""
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._begin_close()
            try:
                wakeup = socket.create_connection(self._address, timeout=0.25)
            except OSError:
                wakeup = None
            if wakeup is not None:
                wakeup.close()
            self._thread.join(self._join_timeout)
            # A wakeup that failed leaves the daemon serving thread parked in
            # select(); it is abandoned here and server_close() closes its socket.
        self.server_close()

    def _serve_until_callback(self) -> None:
        """Serve connections until a callback arrives or shutdown begins."""
        try:
            while not self._received.is_set():
                with self._request_lock:
                    if self._closing:
                        break
                self.handle_request()
        finally:
            self.server_close()

    def _wait(self, timeout: float) -> None:
        """Wait for the callback or time out; always shut down the server."""
        try:
            if not self._received.wait(timeout):
                raise SignInError('timed out waiting for the browser sign-in')
        finally:
            self._close()

    def close_request(self, request: socket.socket | tuple[bytes, socket.socket]) -> None:
        """Close a completed request and clear active ownership.

        Args:
            request: The accepted server request.
        """
        try:
            super().close_request(request)
        finally:
            if isinstance(request, socket.socket):
                with self._request_lock:
                    if self._active_request is request:
                        self._active_request = None

    def get_request(self) -> tuple[socket.socket, object]:
        """Accept and record one callback socket unless closing began.

        Returns:
            The accepted socket and client address.

        Raises:
            OSError: Callback shutdown began before the socket was recorded.
        """
        request, client_address = super().get_request()
        with self._request_lock:
            if self._closing:
                self._close_socket(request)
                raise OSError('callback server is closing')
            self._active_request = request
        return request, client_address

    def handle_error(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        """Suppress expected disconnect errors during callback shutdown.

        Args:
            request: The accepted server request.
            client_address: The client address associated with the request.
        """
        error = sys.exception()
        if self._closing and (
            isinstance(error, ConnectionError)
            or (
                isinstance(error, OSError)
                and error.errno == _WINDOWS_NOT_SOCKET_ERROR
                and sys.platform == 'win32'
            )
        ):
            return
        super().handle_error(request, client_address)


def _authorization_url(endpoint: str, query: dict[str, str]) -> str:
    """Append OAuth parameters while preserving an endpoint query."""
    parts = urlsplit(endpoint)
    generated = urlencode(query)
    combined = '&'.join(value for value in (parts.query, generated) if value)
    return urlunsplit(parts._replace(query=combined))


def _discovery_document(issuer: str) -> dict[str, object]:
    """Fetch and validate an issuer's OIDC discovery document."""
    try:
        response = requests.get(
            f'{issuer.rstrip("/")}/.well-known/openid-configuration',
            allow_redirects=False,
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    except ValueError as exc:
        raise SignInError(str(exc)) from exc
    except requests.RequestException as exc:
        raise SignInError(f'OIDC discovery for {issuer} failed: {exc.__class__.__name__}') from exc
    if response.status_code != _SUCCESS_STATUS:
        raise SignInError(f'OIDC discovery for {issuer} returned {response.status_code}')
    try:
        document: object = response.json()
    except ValueError as exc:
        raise SignInError('OIDC discovery returned a non-JSON body') from exc
    if not isinstance(document, dict):
        raise SignInError('OIDC discovery document is not a JSON object')
    return cast('dict[str, object]', document)


def _post_token_endpoint(
    http: requests.Session,
    token_endpoint: str,
    data: dict[str, str],
    *,
    operation: str,
) -> dict[str, object]:
    """Post one token grant without redirects and require a successful JSON object."""
    try:
        response = http.post(
            token_endpoint,
            allow_redirects=False,
            data=data,
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise SignInError(f'token endpoint unreachable: {exc.__class__.__name__}') from exc
    if response.status_code != _SUCCESS_STATUS:
        raise SignInError(f'{operation} rejected (HTTP {response.status_code})')
    try:
        body: object = response.json()
    except ValueError as exc:
        raise SignInError('token endpoint returned a non-JSON body') from exc
    if not isinstance(body, dict):
        raise SignInError('token endpoint returned a malformed body')
    return cast('dict[str, object]', body)


def _raise_provider_error(callback: _CallbackServer) -> None:
    """Raise the provider's state-valid authorization error, if any."""
    if callback._error is None:
        return
    detail = f': {callback._error_description}' if callback._error_description is not None else ''
    raise SignInError(f'authorization provider returned {callback._error}{detail}')


def _refresh_id_token(
    client_id: str,
    refresh_token: str,
    *,
    token_endpoint: str,
    session: requests.Session | None = None,
) -> tuple[str | None, str | None]:
    """Exchange a refresh token for a fresh ID token."""
    http = session if session is not None else requests.Session()
    fields = _post_token_endpoint(
        http,
        token_endpoint,
        {
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'refresh_token': refresh_token,
        },
        operation='refresh',
    )
    id_token = fields.get('id_token')
    rotated = fields.get('refresh_token')
    return (
        id_token if isinstance(id_token, str) and id_token else None,
        rotated if isinstance(rotated, str) else None,
    )


def credential_namespace() -> tuple[str, str]:
    """Resolve the client and credential issuer from env without network access.

    Read `SG_USER_TOKEN_CLIENT_ID` and optional `SG_USER_TOKEN_ISSUER`,
    stripping surrounding whitespace. An absent or empty issuer selects the
    Google token endpoint as the credential namespace key.

    Returns:
        The client id and issuer key.

    Raises:
        SignInSettingsError: If `SG_USER_TOKEN_CLIENT_ID` is absent or empty
            after stripping.
    """
    client_id = os.environ.get('SG_USER_TOKEN_CLIENT_ID', '').strip()
    if not client_id:
        raise SignInSettingsError('SG_USER_TOKEN_CLIENT_ID is not set')
    issuer = os.environ.get('SG_USER_TOKEN_ISSUER', '').strip()
    return client_id, issuer or _GOOGLE_TOKEN_ENDPOINT


def decode_unverified_payload(id_token: str) -> dict[str, object]:
    """Decode a JWT payload without verifying its signature.

    Args:
        id_token: A compact-serialized JWT.

    Returns:
        The payload claims.

    Raises:
        SignInError: If the token is not a three-part JWT with an object
            payload.
    """
    parts = id_token.split('.')
    if len(parts) != _JWT_PART_COUNT:
        raise SignInError('provider returned a malformed id_token')
    try:
        segment = parts[1]
        padded = segment + '=' * (-len(segment) % 4)
        payload: object = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError as exc:
        raise SignInError('provider returned a malformed id_token') from exc
    if not isinstance(payload, dict):
        raise SignInError('provider returned a malformed id_token')
    return cast('dict[str, object]', payload)


def account_from_id_token(id_token: str) -> str:
    """Derive the credential-store account name from an ID token.

    Read the claim named by `SG_USER_TOKEN_EMAIL_CLAIM`, defaulting to `email`.
    Use the first non-empty string from that claim and `sub`;
    fall back to `unknown` when neither is available.

    Args:
        id_token: Provider ID token used only for display and namespacing.
            Its signature is not verified here.

    Returns:
        The selected account identifier.

    Raises:
        SignInError: If the ID-token payload cannot be decoded.
    """
    payload = decode_unverified_payload(id_token)
    claim = os.environ.get('SG_USER_TOKEN_EMAIL_CLAIM', '').strip() or 'email'
    for name in (claim, 'sub'):
        value = payload.get(name)
        if isinstance(value, str) and value:
            return value
    return 'unknown'


def identity_settings() -> tuple[str, str, str, str]:
    """Resolve client, issuer, and provider endpoints from the environment.

    Use `SG_USER_TOKEN_CLIENT_ID` and optional `SG_USER_TOKEN_ISSUER` as
    resolved by `credential_namespace`. Google uses fixed endpoints;
    another issuer requires an OIDC discovery request and an exact match
    between the configured and discovered issuer.

    Returns:
        The client id, issuer key, authorization endpoint, and token endpoint.

    Raises:
        SignInSettingsError: If `SG_USER_TOKEN_CLIENT_ID` is missing or
            `SG_USER_TOKEN_ISSUER` is not an acceptable URL.
        SignInError: If OIDC discovery fails or returns an unusable document.
    """
    client_id, issuer = credential_namespace()
    if issuer == _GOOGLE_TOKEN_ENDPOINT:
        return (
            client_id,
            _GOOGLE_TOKEN_ENDPOINT,
            _GOOGLE_AUTHORIZATION_ENDPOINT,
            _GOOGLE_TOKEN_ENDPOINT,
        )
    try:
        require_https_or_loopback(issuer, 'SG_USER_TOKEN_ISSUER')
    except ValueError as exc:
        raise SignInSettingsError(str(exc)) from exc
    fields = _discovery_document(issuer)
    if fields.get('issuer') != issuer:
        raise SignInError(
            f'OIDC discovery issuer {fields.get("issuer")!r} != configured {issuer!r}'
        )
    auth_endpoint = fields.get('authorization_endpoint')
    token_endpoint = fields.get('token_endpoint')
    if not isinstance(auth_endpoint, str) or not isinstance(token_endpoint, str):
        raise SignInError('OIDC discovery document lacks endpoints')
    for name, endpoint in (('authorization', auth_endpoint), ('token', token_endpoint)):
        try:
            require_https_or_loopback(endpoint, f'OIDC {name} endpoint')
        except ValueError as exc:
            raise SignInError(str(exc)) from exc
    return client_id, issuer, auth_endpoint, token_endpoint


def sign_in(  # noqa: PLR0913 - injectable public flow boundary
    client_id: str,
    *,
    authorization_endpoint: str,
    token_endpoint: str,
    request_offline_access: bool = True,
    open_browser: Callable[[str], object] = webbrowser.open,
    session: requests.Session | None = None,
    timeout: float = _SIGN_IN_TIMEOUT_SECONDS,
) -> TokenBundle:
    """Run browser PKCE sign-in and return the resulting credentials.

    Open a temporary callback listener on `127.0.0.1` and close it when the
    browser round trip completes or fails. Check authorization state and the
    ID-token nonce; ID-token signature verification remains the service's
    responsibility.

    Args:
        client_id: The installed app OAuth client id.
        authorization_endpoint: The provider authorization endpoint.
        token_endpoint: The provider token endpoint.
        request_offline_access: Whether to request a refresh credential.
        open_browser: Callable opening the authorization URL. It must return a
            truthy value to report a successful launch.
        session: Optional Requests session for the token exchange.
        timeout: Browser round-trip timeout in seconds.

    Returns:
        The ID token and optional refresh token.

    Raises:
        SignInError: If browser launch fails, the callback times out, state or
            nonce mismatches, or the provider exchange fails or is malformed.
    """
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    )
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    callback = _CallbackServer()
    query = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': callback._redirect_uri,
        'scope': _SCOPES,
        'state': state,
        'nonce': nonce,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    if request_offline_access:
        if authorization_endpoint == _GOOGLE_AUTHORIZATION_ENDPOINT:
            query['access_type'] = 'offline'
            query['prompt'] = 'consent'
        else:
            query['scope'] = f'{_SCOPES} offline_access'
    callback(_authorization_url(authorization_endpoint, query), open_browser, timeout)
    if callback._state != state:
        raise SignInError('authorization response state mismatch')
    _raise_provider_error(callback)
    if not callback._code:
        raise SignInError('authorization response carried no code')
    http = session if session is not None else requests.Session()
    fields = _post_token_endpoint(
        http,
        token_endpoint,
        {
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'code': callback._code,
            'code_verifier': verifier,
            'redirect_uri': callback._redirect_uri,
        },
        operation='code exchange',
    )
    id_token = fields.get('id_token')
    if not isinstance(id_token, str) or not id_token:
        raise SignInError('token endpoint returned no id_token')
    if decode_unverified_payload(id_token).get('nonce') != nonce:
        raise SignInError('id_token nonce mismatch')
    refresh = fields.get('refresh_token')
    return TokenBundle(
        id_token=id_token, refresh_token=refresh if isinstance(refresh, str) else None
    )


@dataclass(repr=False)
class _DefaultIdTokenSource:
    """Provide ID tokens through refresh credentials or interactive sign-in."""

    _client_id: str
    _issuer_key: str
    _authorization_endpoint: str
    _token_endpoint: str
    _account: str
    _uses_stored_pointer: bool
    _refresh_token: str | None
    _store_mode: bool

    def __call__(self) -> str:
        """Return an ID token from stored refresh state or interactive sign-in."""
        account_changed = self._sync_account_pointer()
        if self._store_mode and not account_changed and not self._sync_stored_credential():
            return self._interactive()
        if self._refresh_token is None:
            return self._interactive()
        try:
            id_token, rotated = _refresh_id_token(
                self._client_id,
                self._refresh_token,
                token_endpoint=self._token_endpoint,
            )
        except SignInError:
            return self._interactive()
        if rotated is not None:
            self._persist_rotation(rotated)
        if id_token is None:
            return self._interactive()
        return id_token

    def _adopt_interactive(self, bundle: TokenBundle) -> str:
        """Adopt interactive credentials without crossing account storage boundaries."""
        if self._store_mode and account_from_id_token(bundle.id_token) != self._account:
            self._store_mode = False
        self._refresh_token = bundle.refresh_token
        if (
            self._store_mode
            and bundle.refresh_token is not None
            and not store_refresh_token(
                self._issuer_key,
                self._client_id,
                self._account,
                bundle.refresh_token,
            )
        ):
            self._store_mode = False
        return bundle.id_token

    def _interactive(self) -> str:
        """Run interactive sign-in and adopt its credentials."""
        return self._adopt_interactive(
            sign_in(
                self._client_id,
                authorization_endpoint=self._authorization_endpoint,
                token_endpoint=self._token_endpoint,
            )
        )

    def _persist_rotation(self, rotated: str) -> None:
        """Keep a rotated credential in memory and persist it while authoritative."""
        self._refresh_token = rotated
        if self._store_mode and not store_refresh_token(
            self._issuer_key,
            self._client_id,
            self._account,
            rotated,
        ):
            self._store_mode = False

    def _sync_account_pointer(self) -> bool:
        """Adopt a changed stored account and its matching credential."""
        if not self._uses_stored_pointer:
            return False
        current_account = load_account(self._issuer_key, self._client_id) or ''
        if current_account == self._account:
            return False
        current_refresh = (
            load_refresh_token(self._issuer_key, self._client_id, current_account)
            if current_account
            else None
        )
        self._account = current_account
        self._refresh_token = current_refresh
        self._store_mode = current_refresh is not None
        return True

    def _sync_stored_credential(self) -> bool:
        """Reload the selected account's authoritative stored credential."""
        stored = load_refresh_token(self._issuer_key, self._client_id, self._account)
        if stored is None:
            return False
        self._refresh_token = stored
        return True


def default_id_token_source() -> Callable[[], str]:
    """Build a sign-in ID-token source from environment settings.

    Resolve provider settings through `identity_settings`. A non-empty
    `SG_USER_TOKEN_ACCOUNT` fixes account selection; otherwise follow the
    stored last-signed-in account pointer.

    Returns:
        A stateful callable returning a provider ID token. While using stored
        state, it reloads the selected credential before refresh and persists
        rotations.
        Failed writes or a different interactive account switch that state to
        memory-only use. Browser sign-in runs when refresh cannot supply an ID
        token; credentials obtained without stored state remain in memory.
        Calls may raise `SignInError` if interactive sign-in fails.

    Raises:
        SignInError: If settings are missing or discovery fails.
    """
    client_id, issuer_key, auth_endpoint, token_endpoint = identity_settings()
    account = os.environ.get('SG_USER_TOKEN_ACCOUNT', '').strip()
    uses_stored_pointer = not account
    if uses_stored_pointer:
        account = load_account(issuer_key, client_id) or ''
    refresh_token = load_refresh_token(issuer_key, client_id, account) if account else None
    return _DefaultIdTokenSource(
        _client_id=client_id,
        _issuer_key=issuer_key,
        _authorization_endpoint=auth_endpoint,
        _token_endpoint=token_endpoint,
        _account=account,
        _uses_stored_pointer=uses_stored_pointer,
        _refresh_token=refresh_token,
        _store_mode=refresh_token is not None,
    )
