"""Stdlib HTTP layer for the user-token service."""

# pyright: reportPrivateUsage=false

import ipaddress
import logging
from http.server import BaseHTTPRequestHandler
from typing import cast
from urllib.parse import parse_qs

from sg_token_broker._httpbase import (
    BoundedThreadingHTTPServer,
    JsonErrorHandler,
    new_request_id,
    parse_content_length,
    respond,
    split_target,
)
from sg_token_broker._userconfig import normalize_ip
from sg_token_broker._usertoken import UserTokenError, UserTokenRequest, UserTokenService

_REQUEST_TIMEOUT_SECONDS = 30
_SERVER_LOGGER_NAME = 'sg_token_broker.userhttp'

_LOG = logging.getLogger(_SERVER_LOGGER_NAME)


class _Handler(JsonErrorHandler, BaseHTTPRequestHandler):
    """Routes /v1/user-token and /healthz to the user-token service."""

    protocol_version = 'HTTP/1.1'
    server_version = 'sg-user-tokens'
    sys_version = ''
    timeout = _REQUEST_TIMEOUT_SECONDS
    access_logger = _LOG

    def _deny(self, request_id: str, reason: str, status: int, body: dict[str, object]) -> None:
        """Audit a pre-service denial, then answer it."""
        cast('_UserTokenHTTPServer', self.server)._service.log_denied_request(
            reason=reason,
            source_ip=self.client_address[0],
            request_id=request_id,
        )
        respond(self, status, body)

    def _has_body(self) -> bool:
        """Return whether the GET request declares a body or invalid framing."""
        try:
            return parse_content_length(self.headers) != 0
        except ValueError:
            return True

    def _parse_query(self, query: str) -> dict[str, list[str]]:
        """Parse supported query parameters or raise ValueError."""
        params = parse_qs(query, keep_blank_values=True, strict_parsing=False)
        unknown = set(params) - {'refresh', 'token_type'}
        if unknown:
            raise ValueError(f'unknown query parameter {min(unknown)!r}')
        return params

    def _query_flag(self, values: list[str] | None, name: str) -> str | None:
        """Return the single value of a query parameter or raise ValueError."""
        if values is None:
            return None
        if len(values) != 1:
            raise ValueError(f'repeated query parameter {name!r}')
        return values[0]

    def _serve_user_token(self, query: str, request_id: str) -> None:
        """Serve GET /v1/user-token."""
        server = cast('_UserTokenHTTPServer', self.server)
        try:
            params = self._parse_query(query)
            token_type = self._query_flag(params.get('token_type'), 'token_type') or 'rest'
            refresh_raw = self._query_flag(params.get('refresh'), 'refresh')
        except ValueError as exc:
            self._deny(
                request_id,
                'bad_request',
                400,
                {'error': 'bad_request', 'detail': str(exc)},
            )
            return
        source_ip = self.client_address[0]
        try:
            peer = normalize_ip(source_ip)
        except ValueError:
            peer = None
        if peer is not None and peer in server._trusted_proxies:
            forwarded_values = self.headers.get_all('X-Forwarded-For') or []
            forwarded = ','.join(forwarded_values)
            source_ip = forwarded.rsplit(',', 1)[-1].strip() or source_ip
        request = UserTokenRequest(
            authorization=self.headers.get('Authorization', ''),
            source_ip=source_ip,
            request_id=request_id,
            token_type=token_type,
            refresh=refresh_raw == 'true',
        )
        try:
            issued = server._service.issue_token(request)
        except UserTokenError as exc:
            respond(self, exc.status, {'error': exc.error, 'detail': str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - spec: unexpected errors become an opaque 500
            server._service.log_unhandled(request, exc)
            _LOG.exception('unhandled error issuing user token')
            respond(self, 500, {'error': 'internal_error', 'detail': 'internal error'})
            return
        respond(
            self,
            200,
            {
                'token': issued.token,
                'token_type': issued.token_type,
                'login': issued.login,
                'site_url': issued.site_url,
                'expires_at': issued.expires_at.isoformat() if issued.expires_at else None,
                'cache_until': issued.cache_until.isoformat(),
            },
        )

    def do_GET(self) -> None:
        """Route GET requests."""
        request_id = new_request_id()
        if self._has_body():
            self._deny(
                request_id,
                'bad_request',
                400,
                {'error': 'bad_request', 'detail': 'request body not allowed'},
            )
            return
        try:
            parts = split_target(self.path)
        except ValueError:
            self._deny(
                request_id,
                'bad_request',
                400,
                {'error': 'bad_request', 'detail': 'malformed request target'},
            )
            return
        if parts.path == '/healthz':
            respond(self, 200, {'status': 'ok'})
            return
        if parts.path == '/v1/user-token':
            self._serve_user_token(parts.query, request_id)
            return
        self._deny(
            request_id,
            'not_found',
            404,
            {'error': 'not_found', 'detail': 'unknown path'},
        )

    def log_denial(self, reason: str) -> None:
        """Audit a denial the stdlib answered before routing.

        Args:
            reason: Stable audit reason for the denial.
        """
        cast('_UserTokenHTTPServer', self.server)._service.log_denied_request(
            reason=reason,
            source_ip=self.client_address[0],
            request_id=new_request_id(),
        )


class _UserTokenHTTPServer(BoundedThreadingHTTPServer):
    """Threading HTTP server carrying the user-token service reference."""

    error_logger = _LOG

    def __init__(
        self,
        address: tuple[str, int],
        service: UserTokenService,
        trusted_proxies: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(),
    ) -> None:
        """Bind `address` with the user-token service and trusted proxies."""
        super().__init__(address, _Handler)
        self._service = service
        self._trusted_proxies = trusted_proxies


def create_user_token_server(
    bind: str,
    port: int,
    service: UserTokenService,
    *,
    trusted_proxies: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(),
) -> _UserTokenHTTPServer:
    """Create the user-token HTTP server (not yet serving).

    Args:
        bind: Bind address ('' for all interfaces, as Cloud Run requires).
        port: Listening port (Cloud Run's `$PORT`).
        service: The user-token service.
        trusted_proxies: Peer addresses allowed to supply `X-Forwarded-For`.

    Returns:
        A configured server; call `serve_forever()` on it.

    Raises:
        OSError: If the listening socket cannot be created.
    """
    return _UserTokenHTTPServer((bind, port), service, trusted_proxies)
