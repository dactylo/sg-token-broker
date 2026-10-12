"""Serve broker routes through the standard-library HTTP stack."""

# pyright: reportPrivateUsage=false

import base64
import binascii
import ipaddress
import json
import logging
import socket
import ssl
from http.server import BaseHTTPRequestHandler
from typing import cast

from sg_token_broker._config import BrokerConfig
from sg_token_broker._httpbase import (
    BoundedThreadingHTTPServer,
    JsonErrorHandler,
    new_request_id,
    parse_content_length,
    respond,
    split_target,
)
from sg_token_broker._service import (
    BadRequestError,
    BrokerError,
    BrokerService,
    InvalidClientError,
    TokenRequest,
)

_DRAIN_LIMIT_BYTES = 65536
_MAX_BODY_BYTES = 8192
_REQUEST_TIMEOUT_SECONDS = 30
_SERVER_LOGGER_NAME = 'sg_token_broker.http'

_LOG = logging.getLogger(_SERVER_LOGGER_NAME)


class _BrokerHTTPServer(BoundedThreadingHTTPServer):
    """Serve broker requests for `service` at `address`."""

    error_logger = _LOG

    def __init__(self, address: tuple[str, int], service: BrokerService) -> None:
        """Bind `address` and attach the broker service."""
        try:
            host = ipaddress.ip_address(address[0])
        except ValueError:
            self.address_family = socket.AF_INET
        else:
            self.address_family = (
                socket.AF_INET6 if isinstance(host, ipaddress.IPv6Address) else socket.AF_INET
            )
        super().__init__(address, _Handler)
        self._service = service


class _PayloadTooLargeError(BrokerError):
    """Request body exceeded `_MAX_BODY_BYTES`."""

    status = 413
    error = 'payload_too_large'


class _Handler(JsonErrorHandler, BaseHTTPRequestHandler):
    """Routes /v1/token and /healthz to the broker service."""

    protocol_version = 'HTTP/1.1'
    server_version = 'sg-token-broker'
    sys_version = ''
    timeout = _REQUEST_TIMEOUT_SECONDS
    access_logger = _LOG

    def _deny(self, request_id: str, reason: str, status: int, body: dict[str, object]) -> None:
        """Audit a pre-service denial, then answer it."""
        cast('_BrokerHTTPServer', self.server)._service.log_denied_request(
            reason=reason,
            source_ip=self.client_address[0],
            request_id=request_id,
        )
        respond(self, status, body)

    def _drain(self, length: int) -> None:
        """Discard up to `_DRAIN_LIMIT_BYTES` of a rejected body, best effort."""
        remaining = min(length, _DRAIN_LIMIT_BYTES)
        while remaining > 0:
            try:
                chunk = self.rfile.read(min(remaining, 8192))
            except TimeoutError:
                return
            if not chunk:
                return
            remaining -= len(chunk)

    def _parse_basic_auth(self) -> tuple[str, str]:
        """Extract client credentials from the Authorization header."""
        header = self.headers.get('Authorization', '')
        if not header:
            error = InvalidClientError('missing Authorization header')
            error.reason = 'missing_authorization'
            raise error
        scheme, _, encoded = header.partition(' ')
        if scheme.lower() != 'basic' or not encoded:
            error = InvalidClientError('malformed Basic credentials')
            error.reason = 'malformed_authorization'
            raise error
        try:
            decoded = base64.b64decode(encoded.strip(), validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            error = InvalidClientError('malformed Basic credentials')
            error.reason = 'malformed_authorization'
            raise error from exc
        client_id, sep, secret = decoded.partition(':')
        if not sep or not client_id:
            error = InvalidClientError('malformed Basic credentials')
            error.reason = 'malformed_authorization'
            raise error
        return client_id, secret

    def _parse_content_length(self) -> int:
        """Parse a singleton ASCII decimal `Content-Length`, defaulting to zero."""
        try:
            return parse_content_length(self.headers)
        except ValueError as exc:
            raise BadRequestError(str(exc)) from exc

    def _parse_token_request(self, raw: bytes, request_id: str) -> TokenRequest:
        """Parse Basic auth and the JSON body into a TokenRequest."""
        client_id, client_secret = self._parse_basic_auth()
        try:
            body: object = json.loads(raw or b'{}')
        except (ValueError, UnicodeDecodeError) as exc:
            raise BadRequestError('request body is not valid JSON') from exc
        if not isinstance(body, dict):
            raise BadRequestError('request body must be a JSON object')
        fields = cast('dict[str, object]', body)
        scope = fields.get('scope')
        if not isinstance(scope, str) or not scope:
            raise BadRequestError('scope is required')
        token_type = fields.get('token_type', 'session')
        if not isinstance(token_type, str):
            raise BadRequestError('token_type must be a string')
        return TokenRequest(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            token_type=token_type,
            source_ip=self.client_address[0],
            request_id=request_id,
        )

    def _read_body(self) -> bytes:
        """Read the request body, enforcing the framing limits."""
        length = self._parse_content_length()
        if length > _MAX_BODY_BYTES:
            self._drain(length)
            raise _PayloadTooLargeError('request body too large')
        try:
            raw = self.rfile.read(length)
        except TimeoutError as exc:
            raise BadRequestError('incomplete request body') from exc
        if len(raw) != length:
            raise BadRequestError('incomplete request body')
        return raw

    def _route(self, request_id: str) -> str | None:
        """Return the parsed request path, or answer 400 and return None."""
        try:
            return split_target(self.path).path
        except ValueError:
            self._deny(
                request_id,
                'bad_request',
                400,
                {'error': 'bad_request', 'detail': 'malformed request target'},
            )
            return None

    def do_GET(self) -> None:
        """Serve the unauthenticated health check."""
        request_id = new_request_id()
        path = self._route(request_id)
        if path is None:
            return
        if path == '/v1/token':
            self._deny(
                request_id,
                'method_not_allowed',
                405,
                {'error': 'method_not_allowed', 'detail': 'method not allowed'},
            )
            return
        try:
            if self._parse_content_length() != 0:
                raise BadRequestError('request body is not allowed')
        except BrokerError as exc:
            self._deny(
                request_id,
                exc.reason or 'bad_request',
                exc.status,
                {'error': exc.error, 'detail': str(exc)},
            )
            return
        if path == '/healthz':
            respond(self, 200, {'status': 'ok'})
            return
        self._deny(
            request_id,
            'not_found',
            404,
            {'error': 'not_found', 'detail': 'unknown path'},
        )

    def do_POST(self) -> None:
        """Serve POST /v1/token."""
        request_id = new_request_id()
        path = self._route(request_id)
        if path is None:
            return
        if path == '/healthz':
            self._deny(
                request_id,
                'method_not_allowed',
                405,
                {'error': 'method_not_allowed', 'detail': 'method not allowed'},
            )
            return
        if path != '/v1/token':
            self._deny(
                request_id,
                'not_found',
                404,
                {'error': 'not_found', 'detail': 'unknown path'},
            )
            return
        broker_server = cast('_BrokerHTTPServer', self.server)
        try:
            raw = self._read_body()
            request = self._parse_token_request(raw, request_id)
        except (BadRequestError, InvalidClientError, _PayloadTooLargeError) as exc:
            reason = (
                exc.reason if isinstance(exc, InvalidClientError) else exc.reason or 'bad_request'
            )
            self._deny(
                request_id,
                reason,
                exc.status,
                {'error': exc.error, 'detail': str(exc)},
            )
            return
        except Exception as exc:  # noqa: BLE001 - spec: unexpected errors become an opaque 500
            broker_server._service.log_unhandled(
                source_ip=self.client_address[0],
                request_id=request_id,
                exc=exc,
            )
            _LOG.exception('unhandled error issuing token')
            respond(self, 500, {'error': 'internal_error', 'detail': 'internal error'})
            return
        try:
            issued = broker_server._service.issue_token(request)
        except BrokerError as exc:
            respond(
                self,
                exc.status,
                {'error': exc.error, 'detail': str(exc)},
            )
        except Exception as exc:  # noqa: BLE001 - spec: unexpected errors become an opaque 500
            broker_server._service.log_unhandled(
                source_ip=self.client_address[0],
                request_id=request_id,
                exc=exc,
            )
            _LOG.exception('unhandled error issuing token')
            respond(self, 500, {'error': 'internal_error', 'detail': 'internal error'})
        else:
            respond(
                self,
                200,
                {
                    'token': issued.token,
                    'token_type': issued.token_type,
                    'scope': issued.scope,
                    'site_url': issued.site_url,
                    'expires_at': issued.expires_at.isoformat(),
                },
            )

    def log_denial(self, reason: str) -> None:
        """Audit a denial the stdlib answered before routing.

        Args:
            reason: Stable audit reason for the denial.
        """
        cast('_BrokerHTTPServer', self.server)._service.log_denied_request(
            reason=reason,
            source_ip=self.client_address[0],
            request_id=new_request_id(),
        )


def create_server(config: BrokerConfig, service: BrokerService) -> _BrokerHTTPServer:
    """Create the broker HTTP(S) server (not yet serving).

    Args:
        config: Validated broker configuration (TLS material was loaded once at
            config time; it is loaded again here for the live socket).
        service: The broker service.

    Returns:
        A configured server; call `serve_forever()` on it.

    Raises:
        OSError: If the listening socket or TLS files cannot be set up.
        ssl.SSLError: If the TLS material is invalid.
    """
    server = _BrokerHTTPServer((config.server.bind, config.server.port), service)
    if config.server.tls is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=config.server.tls.cert_file, keyfile=config.server.tls.key_file
        )
        server.socket = context.wrap_socket(
            server.socket,
            server_side=True,
            do_handshake_on_connect=False,
        )
    return server
