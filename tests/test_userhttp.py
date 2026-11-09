import datetime
import errno
import ipaddress
import json
import logging
import socket
import threading
from collections.abc import Generator, Iterator, Mapping
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
import requests

from sg_token_broker import _usertoken
from sg_token_broker._audit import AuditLogger
from sg_token_broker._gclaims import ClaimsValidator, Verifier
from sg_token_broker._sg import SGMinter
from sg_token_broker._userconfig import normalize_ip
from sg_token_broker._userhttp import create_user_token_server
from sg_token_broker._users import UserDirectory
from sg_token_broker._usertoken import (
    ServiceAccount,
    UserTokenRequest,
    UserTokenService,
    _IssuedUserToken,
)
from tests.conftest import FakeSG

_AUDIENCE = 'client-id-123.apps.googleusercontent.com'
_DOMAIN = 'studio.example'

_EMAIL = 'jane.exec@studio.example'
_LOGIN = 'jane.exec'
_REST_TYPE = _usertoken._REST_TYPE
_SESSION_TYPE = _usertoken._SESSION_TYPE


class TestAddressFamily:
    def test_ipv6_loopback_bind(self) -> None:
        # Probe OS support separately so a product startup failure cannot be skipped.
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.bind(('::1', 0))
        except OSError as exc:
            if exc.errno in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL}:
                pytest.skip(f'OS IPv6 loopback unavailable: {exc}')
            raise

        server = create_user_token_server('::1', 0, Mock(spec=UserTokenService))
        try:
            assert server.socket.family == socket.AF_INET6
            assert server.server_address[0] == '::1'
        finally:
            server.server_close()


class TestConnectionLifetime:
    def test_health_response_closes_before_a_pipelined_request(
        self, http_only_service_url: str
    ) -> None:
        first = b'GET /healthz HTTP/1.1\r\nHost: svc\r\n\r\n'
        second = b'GET /healthz HTTP/1.1\r\nHost: svc\r\nConnection: close\r\n\r\n'
        raw = _raw_exchange(http_only_service_url, first + second)
        assert raw.startswith(b'HTTP/1.1 200')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1


class TestHealthz:
    def test_ok_without_auth(self, http_only_service_url: str) -> None:
        response = requests.get(f'{http_only_service_url}/healthz', timeout=5)
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}


class TestProviderFaultClassification:
    def test_provider_failure_answers_opaque_500_and_audits_one_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        def verifier(presented: str) -> Mapping[str, object]:
            del presented
            raise requests.RequestException('provider response must remain private')

        with (
            _serve_with_verifier(None, verifier) as url,
            caplog.at_level(logging.INFO, logger='test-userhttp-audit'),
        ):
            response = requests.get(
                f'{url}/v1/user-token',
                headers={'Authorization': 'Bearer x'},
                timeout=5,
            )
        assert response.status_code == 500
        assert response.json() == {'error': 'internal_error', 'detail': 'internal error'}
        events = [
            json.loads(record.getMessage())['event']
            for record in caplog.records
            if record.name == 'test-userhttp-audit'
        ]
        assert events == ['error']


class TestQueryParameters:
    def test_repeated_query_parameter_is_bad_request(self, http_only_service_url: str) -> None:
        response = requests.get(
            f'{http_only_service_url}/v1/user-token?token_type=rest&token_type=session',
            headers={'Authorization': f'Bearer {_EMAIL}'},
            timeout=5,
        )
        assert response.status_code == 400

    def test_session_response_has_null_expires_and_cache_until(self, service_url: str) -> None:
        response = requests.get(
            f'{service_url}/v1/user-token?token_type=session',
            headers={'Authorization': f'Bearer {_EMAIL}'},
            timeout=5,
        )
        assert response.status_code == 200
        body = response.json()
        assert body['expires_at'] is None
        assert isinstance(body['cache_until'], str)

    def test_token_type_and_refresh_reach_the_service(
        self, service_url: str, recorded_requests: list[UserTokenRequest]
    ) -> None:
        response = requests.get(
            f'{service_url}/v1/user-token?token_type=session&refresh=true',
            headers={'Authorization': f'Bearer {_EMAIL}'},
            timeout=5,
        )
        assert response.status_code == 200
        assert recorded_requests[-1].token_type == _SESSION_TYPE
        assert recorded_requests[-1].refresh is True

    def test_token_type_defaults_to_rest(
        self, service_url: str, recorded_requests: list[UserTokenRequest]
    ) -> None:
        requests.get(
            f'{service_url}/v1/user-token',
            headers={'Authorization': f'Bearer {_EMAIL}'},
            timeout=5,
        )
        assert recorded_requests[-1].token_type == _REST_TYPE
        assert recorded_requests[-1].refresh is False


class TestTrustedProxies:
    def test_forwarded_for_honored_from_trusted_peer(
        self, trusted_service_url: str, recorded_requests: list[UserTokenRequest]
    ) -> None:
        requests.get(
            f'{trusted_service_url}/v1/user-token',
            headers={
                'Authorization': f'Bearer {_EMAIL}',
                'X-Forwarded-For': '203.0.113.9',
            },
            timeout=5,
        )
        assert recorded_requests[-1].source_ip == '203.0.113.9'

    def test_forwarded_for_ignored_from_untrusted_peer(
        self, service_url: str, recorded_requests: list[UserTokenRequest]
    ) -> None:
        requests.get(
            f'{service_url}/v1/user-token',
            headers={
                'Authorization': f'Bearer {_EMAIL}',
                'X-Forwarded-For': '203.0.113.9',
            },
            timeout=5,
        )
        assert recorded_requests[-1].source_ip == '127.0.0.1'

    def test_last_forwarded_field_wins_from_trusted_peer(
        self,
        trusted_service_url: str,
        recorded_requests: list[UserTokenRequest],
    ) -> None:
        payload = (
            b'GET /v1/user-token HTTP/1.1\r\n'
            b'Host: svc\r\n'
            + f'Authorization: Bearer {_EMAIL}\r\n'.encode()
            + b'X-Forwarded-For: attacker-controlled\r\n'
            + b'X-Forwarded-For: 198.51.100.7\r\n'
            + b'Connection: close\r\n\r\n'
        )

        raw = _raw_exchange(trusted_service_url, payload)

        assert raw.startswith(b'HTTP/1.1 200')
        assert recorded_requests[-1].source_ip == '198.51.100.7'

    def test_mapped_trusted_proxy_matches_ipv4_peer(
        self,
        mapped_trusted_service_url: str,
        recorded_requests: list[UserTokenRequest],
    ) -> None:
        requests.get(
            f'{mapped_trusted_service_url}/v1/user-token',
            headers={
                'Authorization': f'Bearer {_EMAIL}',
                'X-Forwarded-For': '203.0.113.9',
            },
            timeout=5,
        )
        assert recorded_requests[-1].source_ip == '203.0.113.9'

    def test_pre_service_denial_ignores_forwarded_for_from_untrusted_peer(
        self, http_only_service_url: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        payload = b'GET /nope HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n'
        with caplog.at_level(logging.INFO, logger='test-userhttp-audit'):
            _raw_exchange(http_only_service_url, payload)
        assert json.loads(caplog.records[-1].getMessage())['source_ip'] == '127.0.0.1'

    @pytest.mark.parametrize(
        ('line', 'headers'),
        [
            ('GET /v1/user-token HTTP/1.1', 'Content-Length: 1\r\n'),
            ('GET http://[ HTTP/1.1', ''),
            ('GET /nope HTTP/1.1', ''),
            ('GET /v1/user-token?bogus=1 HTTP/1.1', ''),
            ('POST /healthz HTTP/1.1', ''),
        ],
        ids=['body', 'malformed-target', 'unknown-path', 'bad-query', 'method'],
    )
    def test_pre_service_denials_audit_the_forwarded_client(
        self,
        http_only_trusted_service_url: str,
        caplog: pytest.LogCaptureFixture,
        line: str,
        headers: str,
    ) -> None:
        payload = f'{line}\r\nHost: x\r\nX-Forwarded-For: 203.0.113.9\r\n{headers}\r\n'.encode()
        with caplog.at_level(logging.INFO, logger='test-userhttp-audit'):
            _raw_exchange(http_only_trusted_service_url, payload)
        records = [json.loads(record.getMessage()) for record in caplog.records]
        assert [(entry['event'], entry['source_ip']) for entry in records] == [
            ('deny', '203.0.113.9')
        ]


def _email_verifier(presented: str) -> Mapping[str, object]:
    if presented == 'boom@studio.example':
        raise RuntimeError('verifier exploded')
    if '@' not in presented:
        raise ValueError('forged token')
    return {'aud': _AUDIENCE, 'email': presented, 'email_verified': True, 'hd': _DOMAIN}


@contextmanager
def _serve_with_verifier(
    fake_sg: FakeSG | None,
    verifier: Verifier,
    trusted_proxies: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(),
) -> Generator[str, None, None]:
    if fake_sg is None:
        site_url = 'https://studio.example'
        minter = Mock(spec=SGMinter)
        directory = Mock(spec=UserDirectory)
        directory.resolve_login.side_effect = AssertionError('unexpected SG lookup')
        for method in ('mint_rest_token', 'mint_session_token', 'check_session_token'):
            getattr(minter, method).side_effect = AssertionError('unexpected SG request')
    else:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        fake_sg.human_logins[_LOGIN] = 7
        fake_sg.rpc_unique_human_sessions = True
        fake_sg.rest_credentials = {'usersvc': 'svc-credential'}
        site_url = fake_sg.url
        minter = SGMinter(site_url)
        directory = UserDirectory(site_url, minter, 'usersvc', 'svc-credential')
    service = UserTokenService(
        ServiceAccount(site_url, 'usersvc', 'svc-credential'),
        ClaimsValidator(verifier, [_AUDIENCE], _DOMAIN),
        directory,
        minter,
        AuditLogger(logging.getLogger('test-userhttp-audit')),
        token_types=frozenset({'rest', 'session'}),
    )
    server = create_user_token_server('127.0.0.1', 0, service, trusted_proxies=trusted_proxies)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}'
    finally:
        server.shutdown()
        server.server_close()


def _serve(
    fake_sg: FakeSG | None,
    trusted_proxies: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> Iterator[str]:
    with _serve_with_verifier(fake_sg, _email_verifier, trusted_proxies) as url:
        yield url


@pytest.fixture
def http_only_service_url() -> Iterator[str]:
    yield from _serve(None, frozenset())


@pytest.fixture
def http_only_trusted_service_url() -> Iterator[str]:
    yield from _serve(None, frozenset({normalize_ip('127.0.0.1')}))


@pytest.fixture
def mapped_trusted_service_url(fake_sg: FakeSG) -> Iterator[str]:
    yield from _serve(fake_sg, frozenset({normalize_ip('::ffff:127.0.0.1')}))


@pytest.fixture
def recorded_requests(monkeypatch: pytest.MonkeyPatch) -> list[UserTokenRequest]:
    captured: list[UserTokenRequest] = []
    original = UserTokenService.issue_token

    def record(self: UserTokenService, request: UserTokenRequest) -> _IssuedUserToken:
        captured.append(request)
        return original(self, request)

    monkeypatch.setattr(UserTokenService, 'issue_token', record)
    return captured


@pytest.fixture
def service_url(fake_sg: FakeSG) -> Iterator[str]:
    yield from _serve(fake_sg, frozenset())


def _raw_exchange(service_url: str, payload: bytes) -> bytes:
    host, _, port = service_url.removeprefix('http://').partition(':')
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.sendall(payload)
        sock.settimeout(10)
        chunks: list[bytes] = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b''.join(chunks)


@pytest.fixture
def trusted_service_url(fake_sg: FakeSG) -> Iterator[str]:
    yield from _serve(fake_sg, frozenset({normalize_ip('127.0.0.1')}))


class TestRequestFraming:
    @pytest.mark.parametrize(
        ('length_headers', 'body'),
        [
            (b'Content-Length: 0\r\nContent-Length: 5\r\n', b'xxxxx'),
            (b'Content-Length: 0, 5\r\n', b'xxxxx'),
        ],
        ids=['duplicate', 'malformed'],
    )
    def test_get_ambiguous_length_is_rejected_and_closed(
        self, http_only_service_url: str, length_headers: bytes, body: bytes
    ) -> None:
        head = b'GET /healthz HTTP/1.1\r\nHost: svc\r\n' + length_headers + b'\r\n' + body
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_transfer_encoding_is_rejected_and_closed(
        self, http_only_service_url: str
    ) -> None:
        head = b'GET /healthz HTTP/1.1\r\nHost: svc\r\nTransfer-Encoding: chunked\r\n\r\n'
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_body_is_rejected_and_closed(self, http_only_service_url: str) -> None:
        head = b'GET /healthz HTTP/1.1\r\nHost: svc\r\nContent-Length: 5\r\n\r\nxxxxx'
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_large_nonzero_length_is_rejected_before_routing(
        self, http_only_service_url: str
    ) -> None:
        length = b'0' * 4999 + b'1'
        head = b'GET /nope HTTP/1.1\r\nHost: svc\r\nContent-Length: ' + length + b'\r\n\r\n'
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_large_zero_length_succeeds(self, http_only_service_url: str) -> None:
        length = b'0' * 5000
        head = (
            b'GET /healthz HTTP/1.1\r\nHost: svc\r\nContent-Length: '
            + length
            + b'\r\nConnection: close\r\n\r\n'
        )
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 200')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    @pytest.mark.parametrize(
        'length',
        [b'0 ', b'\xff'],
        ids=['whitespace', 'non-ascii'],
    )
    def test_get_with_malformed_length_is_rejected_and_closed(
        self, http_only_service_url: str, length: bytes
    ) -> None:
        head = b'GET /healthz HTTP/1.1\r\nHost: svc\r\nContent-Length: ' + length + b'\r\n\r\n'
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'connection: close' in raw.lower()
        assert raw.count(b'HTTP/1.1 ') == 1

    def test_get_with_zero_length_succeeds(self, http_only_service_url: str) -> None:
        head = (
            b'GET /healthz HTTP/1.1\r\nHost: svc\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )
        raw = _raw_exchange(http_only_service_url, head)
        assert raw.startswith(b'HTTP/1.1 200')

    def test_head_gets_405_with_no_body(self, http_only_service_url: str) -> None:
        raw = _raw_exchange(http_only_service_url, b'HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n')
        head, _, body = raw.partition(b'\r\n\r\n')
        assert head.startswith(b'HTTP/1.1 405')
        assert b'Content-Length:' in head
        assert body == b''

    def test_unparseable_target_gets_400_without_a_traceback(
        self, http_only_service_url: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.ERROR):
            raw = _raw_exchange(
                http_only_service_url,
                b'GET http://[ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n',
            )
        assert raw.startswith(b'HTTP/1.1 400')
        assert b'"bad_request"' in raw
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]

    @pytest.mark.parametrize(
        'line',
        [
            'POST /healthz HTTP/1.1',
            'POST /v1/user-token HTTP/1.1',
            'PUT /healthz HTTP/1.1',
            'DELETE /v1/user-token HTTP/1.1',
            'TRACE /healthz HTTP/1.1',
            'BREW /healthz HTTP/1.1',
        ],
    )
    def test_wrong_method_is_405(self, http_only_service_url: str, line: str) -> None:
        raw = _raw_exchange(
            http_only_service_url,
            f'{line}\r\nHost: x\r\nContent-Length: 0\r\n\r\n'.encode(),
        )
        assert raw.startswith(b'HTTP/1.1 405')
        assert b'"method_not_allowed"' in raw


class TestUserTokenEndpoint:
    def test_forged_token_is_401(self, http_only_service_url: str) -> None:
        response = requests.get(
            f'{http_only_service_url}/v1/user-token',
            headers={'Authorization': 'Bearer forged'},
            timeout=5,
        )
        assert response.status_code == 401

    def test_issues_token(self, service_url: str, fake_sg: FakeSG) -> None:
        response = requests.get(
            f'{service_url}/v1/user-token',
            headers={'Authorization': f'Bearer {_EMAIL}'},
            timeout=5,
        )
        assert response.status_code == 200
        assert response.headers['Cache-Control'] == 'no-store'
        body = response.json()
        assert body['token'] == f'rest-sudo_as_login:{_LOGIN}'
        assert body['token_type'] == _REST_TYPE
        assert body['login'] == _LOGIN
        assert body['site_url'] == fake_sg.url
        expires_at = datetime.datetime.fromisoformat(body['expires_at'])
        assert expires_at > datetime.datetime.now(datetime.UTC)

    def test_missing_auth_is_401(self, http_only_service_url: str) -> None:
        response = requests.get(f'{http_only_service_url}/v1/user-token', timeout=5)
        assert response.status_code == 401
        assert response.json()['error'] == 'unauthorized'

    @pytest.mark.parametrize(
        'case',
        [
            ('GET /v1/user-token?bogus=1 HTTP/1.1', '', 'bad_request', b'400'),
            ('GET /v1/user-token HTTP/1.1', 'Content-Length: 1\r\n', 'bad_request', b'400'),
            ('GET /nope HTTP/1.1', '', 'not_found', b'404'),
            ('POST /healthz HTTP/1.1', '', 'method_not_allowed', b'405'),
            ('TRACE /healthz HTTP/1.1', '', 'method_not_allowed', b'405'),
            ('GET http://[ HTTP/1.1', '', 'bad_request', b'400'),
            (
                'GET /v1/user-token?token_type=weird HTTP/1.1',
                f'Authorization: Bearer {_EMAIL}\r\n',
                'bad_request',
                b'400',
            ),
        ],
    )
    def test_pre_service_denials_emit_exactly_one_audit_line(
        self,
        http_only_service_url: str,
        caplog: pytest.LogCaptureFixture,
        case: tuple[str, str, str, bytes],
    ) -> None:
        line, headers, reason, status = case
        payload = f'{line}\r\nHost: x\r\n{headers}\r\n'.encode()
        with caplog.at_level(logging.INFO, logger='test-userhttp-audit'):
            raw = _raw_exchange(http_only_service_url, payload)
        assert raw.split(b' ', 2)[1] == status
        lines = [json.loads(record.getMessage()) for record in caplog.records]
        assert [(entry['event'], entry['reason']) for entry in lines] == [('deny', reason)]
        if line != 'GET /v1/user-token?token_type=weird HTTP/1.1':
            assert set(lines[0]) == {'ts', 'event', 'reason', 'source_ip', 'request_id'}

    def test_sg_outage_is_502(self, service_url: str, fake_sg: FakeSG) -> None:
        fake_sg.fail_user_lookup = True
        response = requests.get(
            f'{service_url}/v1/user-token',
            headers={'Authorization': f'Bearer {_EMAIL}'},
            timeout=5,
        )
        assert response.status_code == 502

    def test_source_ip_prefers_forwarded_header(
        self, trusted_service_url: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='test-userhttp-audit'):
            response = requests.get(
                f'{trusted_service_url}/v1/user-token',
                headers={
                    'Authorization': f'Bearer {_EMAIL}',
                    'X-Forwarded-For': 'spoofed, 198.51.100.7',
                },
                timeout=5,
            )
        assert response.status_code == 200
        record = json.loads(caplog.records[-1].getMessage())
        assert record['source_ip'] == '198.51.100.7'

    def test_unexpected_error_is_opaque_500(
        self, http_only_service_url: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='test-userhttp-audit'):
            response = requests.get(
                f'{http_only_service_url}/v1/user-token',
                headers={'Authorization': 'Bearer boom@studio.example'},
                timeout=5,
            )
        assert response.status_code == 500
        assert response.json() == {'error': 'internal_error', 'detail': 'internal error'}
        audit_records = [r for r in caplog.records if r.name == 'test-userhttp-audit']
        assert audit_records, 'no audit event for the unhandled error'
        record = json.loads(audit_records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['reason'] == 'internal_error'
        assert record['detail'] == 'RuntimeError'

    def test_unknown_user_is_403(self, service_url: str) -> None:
        response = requests.get(
            f'{service_url}/v1/user-token',
            headers={'Authorization': 'Bearer ghost@studio.example'},
            timeout=5,
        )
        assert response.status_code == 403
        assert response.json()['error'] == 'forbidden'
