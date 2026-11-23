import base64
import datetime
import json
import ssl
import threading
import traceback
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from sg_token_broker import _oidcverify as oidcverify
from sg_token_broker._oidcverify import OidcUnavailableError, oidc_verifier
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests._tls import write_tls_material

_CLAIM_NOW = 1_800_000_000
_KEY = generate_private_key(SECP256R1())
_KID = 'test-key-1'


class _JwtDatetime(datetime.datetime):
    @classmethod
    def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(_CLAIM_NOW, tz=tz)


class _Provider:
    def __init__(self) -> None:
        outer = self
        self.jwk = _jwk()
        self.jwks_hits = 0
        self.jwks_status = 200

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path.endswith('/.well-known/openid-configuration'):
                    # Discovery answers on any issuer path but always names
                    # the canonical issuer, so a deeper configured issuer
                    # produces a document-issuer mismatch.
                    body = json.dumps(
                        {'issuer': outer.issuer, 'jwks_uri': f'{outer.url}/jwks'}
                    ).encode()
                elif self.path == '/jwks':
                    outer.jwks_hits += 1
                    if outer.jwks_status != 200:
                        self.send_response(outer.jwks_status)
                        self.end_headers()
                        return
                    body = json.dumps({'keys': [outer.jwk]}).encode()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

        self._server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self._server.server_address[1]}'
        self.issuer = self.url
        threading.Thread(
            target=self._server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
        ).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class _RedirectProvider:
    def __init__(self, directory: Path) -> None:
        outer = self

        class DowngradeHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.downgrade_hits += 1
                if self.path == '/discovery':
                    body = json.dumps(
                        {'issuer': outer.issuer, 'jwks_uri': f'{outer.issuer}/jwks'}
                    ).encode()
                elif self.path == '/jwks':
                    body = json.dumps({'keys': [_jwk()]}).encode()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

        class SecureHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path.endswith('/.well-known/openid-configuration'):
                    if outer.redirect_discovery:
                        self.send_response(302)
                        self.send_header('Location', f'{outer.downgrade_url}/discovery')
                        self.end_headers()
                        return
                    body = json.dumps(
                        {'issuer': outer.issuer, 'jwks_uri': f'{outer.issuer}/jwks'}
                    ).encode()
                elif self.path == '/jwks':
                    self.send_response(302)
                    self.send_header('Location', f'{outer.downgrade_url}/jwks')
                    self.end_headers()
                    return
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

        self.downgrade_hits = 0
        self.redirect_discovery = False
        self._downgrade_server = ThreadingHTTPServer(('127.0.0.1', 0), DowngradeHandler)
        downgrade_port = self._downgrade_server.server_address[1]
        self.downgrade_url = f'http://0.0.0.0:{downgrade_port}'
        self._server = ThreadingHTTPServer(('127.0.0.1', 0), SecureHandler)
        certificate_path, key_path = write_tls_material(directory)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate_path, key_path)
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.issuer = f'https://127.0.0.1:{self._server.server_address[1]}'
        self.certificate_path = certificate_path
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = str(certificate_path)
        threading.Thread(
            target=self._downgrade_server.serve_forever,
            kwargs={'poll_interval': 0.01},
            daemon=True,
        ).start()
        threading.Thread(
            target=self._server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
        ).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._downgrade_server.shutdown()
        self._downgrade_server.server_close()


class TestOidcVerifier:
    def test_first_unknown_kid_fetches_jwks_once(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)

        kid = 'provider-private-key-identifier'
        with pytest.raises(ValueError, match='signing key') as caught:
            verify(_sign(_claims(provider), kid=kid))
        assert kid not in ''.join(traceback.format_exception(caught.value))

        assert provider.jwks_hits == 1

    def test_jwks_http_failure_is_operational(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        provider.jwks_status = 503
        with pytest.raises(requests.RequestException, match='OIDC JWKS returned HTTP 503'):
            verify(_sign(_claims(provider)))

    def test_missing_pyjwt_raises_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail(name: str) -> object:
            raise ImportError(name)

        monkeypatch.setattr('sg_token_broker._oidcverify.importlib.import_module', fail)
        with pytest.raises(OidcUnavailableError):
            oidc_verifier('https://idp.example', ('ES256',))

    def test_rejects_a_token_signed_by_another_key(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        other_key = generate_private_key(SECP256R1())
        forged = jwt.encode(_claims(provider), other_key, algorithm='ES256', headers={'kid': _KID})
        with pytest.raises(ValueError, match='Signature verification failed'):
            verify(forged)

    def test_rejects_deeply_nested_header(self, provider: _Provider) -> None:
        # PyJWT before 2.14 let RecursionError escape header parsing. The verifier must
        # report an ordinary invalid token, before any JWKS request.
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        depth = 200_000
        header = base64.urlsafe_b64encode(b'[' * depth + b']' * depth).rstrip(b'=').decode()
        with pytest.raises(ValueError, match=r'[Hh]eader'):
            verify(f'{header}.e30.c2ln')
        assert provider.jwks_hits == 0

    def test_rejects_disallowed_algorithm(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('RS256',), timeout=STALL_TIMEOUT_SECONDS)
        with pytest.raises(ValueError, match='specified alg value is not allowed'):
            verify(_sign(_claims(provider)))

    def test_rejects_discovery_downgrade_redirect(
        self, redirect_provider: _RedirectProvider
    ) -> None:
        redirect_provider.redirect_discovery = True
        with pytest.raises(requests.RequestException, match='redirect'):
            oidc_verifier(
                redirect_provider.issuer,
                ('ES256',),
                session=redirect_provider.session,
                timeout=STALL_TIMEOUT_SECONDS,
            )
        assert redirect_provider.downgrade_hits == 0

    def test_rejects_discovery_issuer_mismatch(self, provider: _Provider) -> None:
        with pytest.raises(ValueError, match='issuer'):
            oidc_verifier(f'{provider.issuer}/tenant', ('ES256',), timeout=STALL_TIMEOUT_SECONDS)

    def test_rejects_expired_token(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        with pytest.raises(ValueError, match=r'[Ee]xpired'):
            verify(_sign(_claims(provider, exp=_CLAIM_NOW - 10)))

    def test_rejects_jwks_downgrade_redirect(self, redirect_provider: _RedirectProvider) -> None:
        verify = oidc_verifier(
            redirect_provider.issuer,
            ('ES256',),
            session=redirect_provider.session,
            timeout=STALL_TIMEOUT_SECONDS,
        )
        with pytest.raises(requests.RequestException, match='redirect'):
            verify(_sign(_claims(redirect_provider)))
        assert redirect_provider.downgrade_hits == 0

    def test_rejects_non_object_decoded_payload(
        self, provider: _Provider, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)

        def decode(*_args: object, **_kwargs: object) -> list[object]:
            return []

        monkeypatch.setattr(jwt, 'decode', decode)
        with pytest.raises(ValueError, match=r'^decoded token payload is not an object$'):
            verify(_sign(_claims(provider)))

    def test_rejects_partial_issuer_match(self, provider: _Provider) -> None:
        # PyJWT 2.10.0 accepted an `iss` that is a substring of the expected issuer
        # (GHSA-75c5-xw7c-p5pm).
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        with pytest.raises(ValueError, match=r'[Ii]ssuer'):
            verify(_sign(_claims(provider, iss=provider.issuer[:-1])))

    @pytest.mark.usefixtures('no_requests')
    def test_rejects_symmetric_algorithm_configuration(self) -> None:
        with pytest.raises(ValueError, match='asymmetric'):
            oidc_verifier('https://idp.example', ('HS256',))

    def test_rejects_token_without_exp(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        claims = _claims(provider)
        del claims['exp']
        with pytest.raises(ValueError, match='exp'):
            verify(_sign(claims))

    def test_rejects_wrong_issuer(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        with pytest.raises(ValueError, match=r'[Ii]ssuer'):
            verify(_sign(_claims(provider, iss='https://elsewhere.example')))

    def test_verifies_a_signed_token(self, provider: _Provider) -> None:
        verify = oidc_verifier(provider.issuer, ('ES256',), timeout=STALL_TIMEOUT_SECONDS)
        payload = verify(_sign(_claims(provider)))
        assert payload['email'] == 'jane@studio.example'


class _StubResponse:
    def __init__(self, status: int, body: bytes, *, redirect: bool = False) -> None:
        self.status_code = status
        self.is_redirect = redirect
        self.is_permanent_redirect = False
        self._body = body

    def json(self) -> object:
        return json.loads(self._body)


class _StubSession:
    def __init__(self, response: _StubResponse) -> None:
        self._response = response

    def get(self, url: str, *, timeout: float, allow_redirects: bool) -> _StubResponse:
        del url, timeout, allow_redirects
        return self._response


def _capture_unknown_key_error(
    resolver: Callable[[str], object],
    presented: str,
    errors: list[BaseException],
    finished: threading.Event,
    wake: threading.Event,
) -> None:
    try:
        with pytest.raises(BaseException, match=r'(?s).*') as raised:
            resolver(presented)
        errors.append(raised.value)
    finally:
        finished.set()
        wake.set()


def _jwk(*, kid: str = _KID) -> dict[str, object]:
    algorithm = jwt.get_algorithm_by_name('ES256')
    jwk = json.loads(algorithm.to_jwk(_KEY.public_key()))
    return jwk | {'kid': kid, 'use': 'sig', 'alg': 'ES256'}


def _resolver(
    fetch_jwks: Callable[[], dict[str, object]], now: list[float]
) -> oidcverify._SigningKeyResolver:
    client = jwt.PyJWKClient('https://idp.example/jwks', cache_keys=True)
    return oidcverify._SigningKeyResolver(
        client,
        jwt,
        fetch_jwks,
        clock=lambda: now[0],
    )


def _sign(claims: dict[str, object], *, algorithm: str = 'ES256', kid: str = _KID) -> str:
    return jwt.encode(claims, _KEY, algorithm=algorithm, headers={'kid': kid})


@pytest.fixture
def provider() -> Iterator[_Provider]:
    fake = _Provider()
    yield fake
    fake.close()


def _claims(provider: _Provider | _RedirectProvider, **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        'iss': provider.issuer,
        'aud': 'client-1',
        'exp': _CLAIM_NOW + 300,
        'iat': _CLAIM_NOW,
        'email': 'jane@studio.example',
    }
    return base | overrides


@pytest.fixture(autouse=True)
def fixed_jwt_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('jwt.api_jwt.datetime', _JwtDatetime)


@pytest.fixture
def redirect_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[_RedirectProvider]:
    fake = _RedirectProvider(tmp_path)
    monkeypatch.setenv('SSL_CERT_FILE', str(fake.certificate_path))
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,0.0.0.0')
    yield fake
    fake.close()


def test_cached_matching_key_survives_failed_refresh_cooldown() -> None:
    now = [0.0]
    fetch_count = 0
    transport_error = oidcverify._OidcTransportError

    def fetch_jwks() -> dict[str, object]:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 1:
            return {'keys': [_jwk()]}
        raise transport_error('provider unavailable')

    resolver = _resolver(fetch_jwks, now)
    assert cast('jwt.PyJWK', resolver(_sign({'sub': 'known'}))).key_id == _KID
    now[0] = 5.0
    with pytest.raises(requests.RequestException):
        resolver(_sign({'sub': 'unknown'}, kid='unknown'))

    signing_key = cast('jwt.PyJWK', resolver(_sign({'sub': 'known-again'})))

    assert signing_key.key_id == _KID
    assert fetch_count == 2


def test_discovery_refusal_excludes_session_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    session = requests.Session()
    marker = 'transport-private-marker'
    session.headers['Authorization'] = marker

    def refuse(request: requests.PreparedRequest, **_kwargs: object) -> requests.Response:
        return Mock(
            status_code=401,
            is_redirect=False,
            is_permanent_redirect=False,
            json=Mock(
                return_value={
                    'error': 'invalid_client',
                    'error_description': request.headers['Authorization'],
                }
            ),
        )

    monkeypatch.setattr(session, 'send', refuse)
    with pytest.raises(requests.RequestException, match='invalid_client') as caught:
        oidc_verifier('https://issuer.example', ['ES256'], session=session)
    assert marker not in ''.join(traceback.format_exception(caught.value))


@pytest.mark.parametrize(
    'response',
    [
        _StubResponse(302, b'', redirect=True),
        _StubResponse(503, b'{}'),
        _StubResponse(200, b'<html>error</html>'),
        _StubResponse(200, b'[]'),
    ],
    ids=['redirect', 'non-200', 'non-json', 'non-object'],
)
def test_every_document_fault_is_a_transport_error(response: _StubResponse) -> None:
    fetch = oidcverify._fetch_json_without_redirects
    with pytest.raises(requests.RequestException):
        fetch(
            cast('requests.Session', _StubSession(response)),
            'https://idp.example/jwks',
            1.0,
            'OIDC JWKS',
        )


def test_failed_attempt_is_replayed_without_io_until_recovery_boundary() -> None:
    now = [0.0]
    fetches: list[float] = []
    available = [False]
    transport_error = oidcverify._OidcTransportError

    def fetch_jwks() -> dict[str, object]:
        fetches.append(now[0])
        if not available[0]:
            raise transport_error('provider unavailable')
        return {'keys': [_jwk(kid='recovered-key')]}

    resolver = _resolver(fetch_jwks, now)
    with pytest.raises(requests.RequestException):
        resolver(_sign({'sub': 'one'}, kid='recovered-key'))
    now[0] = 4.999
    with pytest.raises(requests.RequestException):
        resolver(_sign({'sub': 'two'}, kid='another-key'))
    available[0] = True
    now[0] = 5.0

    signing_key = cast(
        'jwt.PyJWK',
        resolver(_sign({'sub': 'three'}, kid='recovered-key')),
    )

    assert signing_key.key_id == 'recovered-key'
    assert fetches == [0.0, 5.0]


def test_issuer_refuses_embedded_credentials() -> None:
    session = Mock()
    with pytest.raises(ValueError, match='credential') as caught:
        oidc_verifier('https://someone:private@idp.example', ['ES256'], session=session)
    assert 'private' not in str(caught.value)
    session.get.assert_not_called()


@pytest.mark.parametrize(
    ('site', 'message'),
    [
        ('discovery', 'discovery at https://127.0.0.1:1 could not be sent: '),
        ('JWKS', 'JWKS at https://127.0.0.1:1 could not be sent: '),
    ],
)
def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: str, message: str
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    with pytest.raises(requests.RequestException) as caught:
        oidcverify._fetch_json_without_redirects(
            requests.Session(), 'https://127.0.0.1:1', STALL_TIMEOUT_SECONDS, site
        )
    assert caught.value.__suppress_context__
    assert str(caught.value).startswith(message)
    assert str(missing) in str(caught.value)


@pytest.mark.parametrize('mode', ['mismatch', 'refusal', 'transport'])
def test_discovery_errors_hide_configured_and_reflected_credentials(mode: str) -> None:
    issuer = 'https://idp.example/tenant?key=query-value#frag-value'
    body = (
        {'issuer': 'reflected-provider-value'}
        if mode == 'mismatch'
        else {
            'error': 'invalid_request',
            'error_description': 'issuer refused query-value ' + 'x' * 300,
        }
    )
    response = Mock(
        status_code=200 if mode == 'mismatch' else 400,
        is_redirect=False,
        is_permanent_redirect=False,
        json=Mock(return_value=body),
    )
    session = Mock(
        get=Mock(
            return_value=response,
            side_effect=requests.ConnectionError(issuer) if mode == 'transport' else None,
        )
    )
    with pytest.raises((ValueError, requests.RequestException)) as caught:
        oidc_verifier(issuer, ['ES256'], session=session)
    message = str(caught.value)
    assert 'idp.example' in message
    assert 'discovery' in message
    assert all(
        part not in message
        for part in ('password', 'query-value', 'frag-value', 'reflected-provider-value')
    )
    if mode == 'refusal':
        assert '400' in message
        assert 'invalid_request' in message
        assert 'issuer refused' not in message
        assert 'x' * 121 not in message


def test_overlapping_unknown_kids_fetch_once_without_concurrent_io() -> None:
    now = [0.0]
    counters_lock = threading.Lock()
    contention_attempted = threading.Event()
    fetch_entered = threading.Event()
    release_fetch = threading.Event()
    first_finished = threading.Event()
    second_finished = threading.Event()
    fetch_calls = 0
    active_fetches = 0
    maximum_active_fetches = 0
    errors: list[BaseException] = []

    def fetch_jwks() -> dict[str, object]:
        nonlocal active_fetches, fetch_calls, maximum_active_fetches
        with counters_lock:
            fetch_calls += 1
            active_fetches += 1
            maximum_active_fetches = max(maximum_active_fetches, active_fetches)
        fetch_entered.set()
        release_fetch.wait()
        with counters_lock:
            active_fetches -= 1
        return {'keys': [_jwk()]}

    resolver = _resolver(fetch_jwks, now)
    resolver_state = vars(resolver)
    resolver_lock = cast('threading.Lock', resolver_state['_lock'])

    class ContentionObservedLock:
        def __enter__(self) -> None:
            if resolver_lock.acquire(blocking=False):
                return
            contention_attempted.set()
            resolver_lock.acquire()

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            del exc_type, exc, traceback
            resolver_lock.release()

    resolver_state['_lock'] = ContentionObservedLock()

    first_thread = threading.Thread(
        target=_capture_unknown_key_error,
        args=(
            resolver,
            _sign({'sub': 'one'}, kid='unknown-one'),
            errors,
            first_finished,
            fetch_entered,
        ),
    )
    second_thread = threading.Thread(
        target=_capture_unknown_key_error,
        args=(
            resolver,
            _sign({'sub': 'two'}, kid='unknown-two'),
            errors,
            second_finished,
            contention_attempted,
        ),
    )
    first_thread.start()
    try:
        fetch_entered.wait()
        assert not first_finished.is_set(), 'first resolver exited before JWKS fetch'
        second_thread.start()
        contention_attempted.wait()
        assert not second_finished.is_set(), 'second resolver exited before lock contention'
    finally:
        release_fetch.set()
        first_thread.join()
        if second_thread.ident is not None:
            second_thread.join()

    assert fetch_calls == 1
    assert maximum_active_fetches == 1
    assert len(errors) == 2
    assert all(isinstance(exc, jwt.PyJWKClientError) for exc in errors)


def test_per_kid_cache_survives_expired_jwk_set_during_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    cache_now = [0.0]
    fetch_count = 0
    available = [True]
    transport_error = oidcverify._OidcTransportError
    clock = SimpleNamespace(monotonic=lambda: cache_now[0])
    monkeypatch.setattr('jwt.jwk_set_cache.time', clock)
    monkeypatch.setattr('jwt.api_jwk.time', clock)

    def fetch_jwks() -> dict[str, object]:
        nonlocal fetch_count
        fetch_count += 1
        if not available[0]:
            raise transport_error('provider unavailable')
        return {'keys': [_jwk()]}

    resolver = _resolver(fetch_jwks, now)
    assert cast('jwt.PyJWK', resolver(_sign({'sub': 'known'}))).key_id == _KID
    cache_now[0] = 300.001
    now[0] = 5.0
    available[0] = False

    signing_key = cast('jwt.PyJWK', resolver(_sign({'sub': 'known-again'})))

    assert signing_key.key_id == _KID
    assert fetch_count == 1


def test_unknown_kids_share_successful_fetch_cooldown_and_retry_at_boundary() -> None:
    now = [0.0]
    fetches: list[float] = []
    published = [[_jwk()]]

    def fetch_jwks() -> dict[str, object]:
        fetches.append(now[0])
        return {'keys': published[0]}

    resolver = _resolver(fetch_jwks, now)
    with pytest.raises(jwt.PyJWKClientError, match='signing key'):
        resolver(_sign({'sub': 'one'}, kid='unknown-one'))
    now[0] = 4.999
    with pytest.raises(jwt.PyJWKClientError, match='signing key'):
        resolver(_sign({'sub': 'two'}, kid='unknown-two'))
    published[0] = [_jwk(), _jwk(kid='new-key')]
    now[0] = 5.0

    signing_key = cast('jwt.PyJWK', resolver(_sign({'sub': 'three'}, kid='new-key')))

    assert signing_key.key_id == 'new-key'
    assert fetches == [0.0, 5.0]
