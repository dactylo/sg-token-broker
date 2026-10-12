"""Fetch and locally cache SG tokens from the broker."""

import datetime
import math
import os
import threading
import time
from dataclasses import dataclass, field
from typing import cast

import requests

from sg_token_broker._config import CLIENT_ID_MAX_CHARS, is_client_id, is_credential_text
from sg_token_broker._urlpolicy import require_https_or_loopback

_ENV_PREFIX = 'SG_TOKEN_BROKER'
_REFRESH_MARGIN_SECONDS = 60.0
_RETRY_BACKOFF_SECONDS = 0.5
_SERVER_ERROR_STATUS = 500
_SESSION_TYPE = 'session'
_SUCCESS_STATUS = 200


class BrokerClientError(Exception):
    """The broker could not be reached or refused the request."""


@dataclass(frozen=True)
class ClientOptions:
    """Tunable timeouts and retry behavior for `BrokerClient`.

    Attributes:
        timeout: Per-request timeout in seconds. Defaults to `10.0`.
        retries: Number of retries after the initial request attempt. Defaults
            to `2`.
        refresh_margin: Seconds before reported expiry when a cached token is
            refreshed. Defaults to `60.0`.

    Raises:
        ValueError: If `timeout` is non-finite or not greater than zero, or if
            `retries` is negative.
    """

    timeout: float = 10.0
    retries: int = 2
    refresh_margin: float = _REFRESH_MARGIN_SECONDS

    def __post_init__(self) -> None:
        """Raise ValueError for non-finite or non-positive timeouts and negative retries."""
        if not (math.isfinite(self.timeout) and self.timeout > 0):
            raise ValueError(f'timeout must be finite and greater than zero, got {self.timeout}')
        if self.retries < 0:
            raise ValueError(f'retries must be >= 0, got {self.retries}')


@dataclass(frozen=True)
class TokenResponse:
    """Represent a token issued by the broker.

    Attributes:
        token: Issued token credential.
        token_type: Issued token type, `session` or `rest`.
        scope: Broker scope authorized for the token.
        site_url: Base URL of the SG site.
        expires_at: Broker refresh deadline. For REST tokens it is derived from
            SG's reported lifetime with a safety margin; for sessions it is an
            advisory reuse deadline, not an SG expiration.
    """

    token: str = field(repr=False)
    token_type: str
    scope: str
    site_url: str
    expires_at: datetime.datetime


class BrokerClient:
    """Fetches and locally caches SG tokens from the broker service.

    The lock is held across the network round trip; concurrent callers
    serialize. Accepted tradeoff.
    """

    def __init__(
        self,
        broker_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        *,
        options: ClientOptions | None = None,
        session: requests.Session | None = None,
    ) -> None:
        """Configure broker access, credentials, and retry behavior.

        Args:
            broker_url: Broker base URL. Defaults to `$SG_TOKEN_BROKER_URL`.
            client_id: Client identifier. Defaults to
                `$SG_TOKEN_BROKER_CLIENT_ID`.
            client_secret: Client secret. Defaults to
                `$SG_TOKEN_BROKER_CLIENT_SECRET`.
            options: Timeout and retry tuning. Defaults to `ClientOptions`.
            session: Optional preconfigured Requests session. Defaults to a new
                session.

        Raises:
            BrokerClientError: If any setting is missing, credential text is
                invalid, or the broker URL is malformed, unsupported, or
                insecure.
        """
        self._broker_url = (broker_url or os.environ.get(f'{_ENV_PREFIX}_URL', '')).rstrip('/')
        self._client_id = client_id or os.environ.get(f'{_ENV_PREFIX}_CLIENT_ID', '')
        self._client_secret = client_secret or os.environ.get(f'{_ENV_PREFIX}_CLIENT_SECRET', '')
        if not (self._broker_url and self._client_id and self._client_secret):
            raise BrokerClientError(
                f'broker settings missing; set {_ENV_PREFIX}_URL, {_ENV_PREFIX}_CLIENT_ID, '
                f'and {_ENV_PREFIX}_CLIENT_SECRET or pass them explicitly'
            )
        if not is_client_id(self._client_id):
            raise BrokerClientError(
                f'client id must be 1..{CLIENT_ID_MAX_CHARS} printable ASCII characters '
                'with no colon or space'
            )
        if not is_credential_text(self._client_secret):
            raise BrokerClientError(
                'client secret must be non-empty printable ASCII with no spaces'
            )
        try:
            require_https_or_loopback(self._broker_url, 'broker URL')
        except ValueError as exc:
            raise BrokerClientError(str(exc)) from exc
        self._options = options if options is not None else ClientOptions()
        self._session = session if session is not None else requests.Session()
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], TokenResponse] = {}

    @staticmethod
    def _detail(response: requests.Response) -> str:
        """Extract the error detail from a broker error response, best-effort."""
        try:
            body: object = response.json()
        except ValueError:
            return ''
        if isinstance(body, dict):
            return str(cast('dict[str, object]', body).get('detail', ''))
        return ''

    def _near_expiry(self, token: TokenResponse) -> bool:
        """Return True if the token is within the refresh margin of expiry."""
        now = datetime.datetime.now(datetime.UTC)
        return (token.expires_at - now).total_seconds() <= self._options.refresh_margin

    @staticmethod
    def _parse(body: object) -> TokenResponse:
        """Build a `TokenResponse` from the broker's JSON body."""
        if not isinstance(body, dict):
            raise BrokerClientError('malformed broker response')
        fields = cast('dict[str, object]', body)
        values: dict[str, str] = {}
        for name in ('token', 'token_type', 'scope', 'site_url', 'expires_at'):
            value = fields.get(name)
            if not isinstance(value, str) or not value:
                raise BrokerClientError(f'malformed broker response: bad {name}')
            values[name] = value
        try:
            expires_at = datetime.datetime.fromisoformat(values['expires_at'])
        except ValueError as exc:
            raise BrokerClientError('malformed broker response: bad expires_at') from exc
        if expires_at.tzinfo is None or expires_at.tzinfo.utcoffset(expires_at) is None:
            raise BrokerClientError('malformed broker response: naive expires_at')
        return TokenResponse(
            token=values['token'],
            token_type=values['token_type'],
            scope=values['scope'],
            site_url=values['site_url'],
            expires_at=expires_at,
        )

    def _request_token(self, scope: str, token_type: str) -> TokenResponse:
        """Request a broker token with retries for transient failures."""
        last_error: Exception | None = None
        for attempt in range(self._options.retries + 1):
            if attempt:
                time.sleep(_RETRY_BACKOFF_SECONDS * attempt)
            try:
                response = self._session.post(
                    f'{self._broker_url}/v1/token',
                    json={'scope': scope, 'token_type': token_type},
                    auth=(self._client_id, self._client_secret),
                    timeout=self._options.timeout,
                )
            except requests.RequestException as exc:
                last_error = exc
                continue
            if response.status_code >= _SERVER_ERROR_STATUS:
                last_error = BrokerClientError(f'broker returned HTTP {response.status_code}')
                continue
            if response.status_code != _SUCCESS_STATUS:
                raise BrokerClientError(
                    f'broker refused (HTTP {response.status_code}): {self._detail(response)}'
                )
            try:
                body: object = response.json()
            except ValueError as exc:
                raise BrokerClientError('broker returned 200 with a non-JSON body') from exc
            token = self._parse(body)
            if token.scope != scope:
                raise BrokerClientError('broker response scope does not match the request')
            if token.token_type != token_type:
                raise BrokerClientError('broker response token_type does not match the request')
            return token
        raise BrokerClientError(f'cannot reach broker at {self._broker_url}: {last_error}')

    def fetch_token(self, scope: str, token_type: str = _SESSION_TYPE) -> TokenResponse:
        """Return a token for the scope, fetching from the broker as needed.

        Args:
            scope: Broker scope name (e.g. `read_all`).
            token_type: `session` (default) or `rest`.

        Returns:
            The cached or newly fetched token. Refresh decisions use the
            broker-reported deadline; cached tokens are not probed for SG
            acceptance.

        Raises:
            BrokerClientError: If the broker is unreachable, refuses the
                request, or returns a malformed or mismatched response.
        """
        key = (scope, token_type)
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None and not self._near_expiry(cached):
                return cached
            fresh = self._request_token(scope, token_type)
            self._cache[key] = fresh
            return fresh


def fetch_token(scope: str, token_type: str = _SESSION_TYPE) -> TokenResponse:
    """Fetch a broker token using settings from the environment.

    Args:
        scope: Broker scope name.
        token_type: `session` (default) or `rest`.

    Returns:
        The token returned by a new `BrokerClient`. The broker may reuse a
        cached token without probing its current SG acceptance.

    Raises:
        BrokerClientError: If settings are missing or invalid, the broker is
            unreachable or refuses, or its response is malformed or mismatched.
    """
    return BrokerClient().fetch_token(scope, token_type)
