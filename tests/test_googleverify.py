import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import jwt
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.auth.transport import requests as google_transport

from sg_token_broker import _googleverify
from sg_token_broker._googleverify import VerifierUnavailableError, google_auth_verifier
from tests._tls import write_tls_material


class TestGoogleAuthVerifier:
    def test_missing_cachecontrol_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = _build_stub_modules(lambda presented: {'sub': presented})

        def import_module(name: str) -> object:
            if name == 'cachecontrol.cache':
                raise ImportError(name)
            return stubs.modules[name]

        monkeypatch.setattr(_googleverify.importlib, 'import_module', import_module)
        with pytest.raises(VerifierUnavailableError, match='google'):
            google_auth_verifier()

    def test_missing_google_auth_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        stubs = _build_stub_modules(lambda presented: {'sub': presented})

        def import_module(name: str) -> object:
            if name == 'google.auth.exceptions':
                raise ImportError(name)
            return stubs.modules[name]

        monkeypatch.setattr(_googleverify.importlib, 'import_module', import_module)
        with pytest.raises(VerifierUnavailableError, match='google'):
            google_auth_verifier()

    def test_reuses_cached_request_across_verifications(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        subjects = {'first': 'one', 'second': 'two'}
        stubs = _build_stub_modules(lambda presented: {'sub': subjects[presented]})
        _install_stub_modules(monkeypatch, stubs)

        verify = google_auth_verifier()
        results = [verify('first'), verify('second')]

        assert results == [{'sub': 'one'}, {'sub': 'two'}]
        assert len(stubs.request_instances) == 1
        assert len(stubs.cachecontrol_calls) == 1
        cachecontrol_call = stubs.cachecontrol_calls[0]
        assert isinstance(cachecontrol_call.session, requests.Session)
        assert isinstance(cachecontrol_call.cache, _FakeDictCache)
        assert stubs.request_instances[0].session is cachecontrol_call.wrapped_session
        assert [call.presented for call in stubs.verify_calls] == ['first', 'second']
        assert all(call.clock_skew_in_seconds == 10 for call in stubs.verify_calls)

    def test_transport_error_has_local_certificate_diagnosis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        error = _TransportError('cert fetch failed')

        def raise_transport_error(presented: str) -> Mapping[str, object]:
            del presented
            raise error

        stubs = _build_stub_modules(raise_transport_error)
        _install_stub_modules(monkeypatch, stubs)

        verify = google_auth_verifier()
        with pytest.raises(RuntimeError, match='Google certificate') as caught:
            verify('whatever-value')
        assert type(error).__name__ in str(caught.value)
        assert 'cert fetch failed' not in str(caught.value)
        assert caught.value.__suppress_context__

    def test_wraps_google_auth_errors_as_value_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        def reject(presented: str) -> Mapping[str, object]:
            del presented
            raise _GoogleAuthError('Wrong issuer.')

        stubs = _build_stub_modules(reject)
        _install_stub_modules(monkeypatch, stubs)

        verify = google_auth_verifier()
        with pytest.raises(ValueError, match='Google identity token verification failed'):
            verify('whatever-value')


@dataclass(frozen=True)
class _CacheControlCall:
    cache: object
    session: object
    wrapped_session: object


class _FakeDictCache:
    pass


@dataclass(frozen=True)
class _FakeRequest:
    session: object | None


class _GoogleAuthError(Exception):
    pass


@dataclass(frozen=True)
class _VerifyCall:
    clock_skew_in_seconds: int
    presented: str


@dataclass(frozen=True)
class _StubModules:
    cachecontrol_calls: list[_CacheControlCall]
    modules: dict[str, object]
    request_instances: list[_FakeRequest]
    verify_calls: list['_VerifyCall']


class _TransportError(_GoogleAuthError):
    pass


def _build_stub_modules(
    behavior: Callable[[str], Mapping[str, object]],
) -> _StubModules:
    cachecontrol_calls: list[_CacheControlCall] = []
    request_instances: list[_FakeRequest] = []
    verify_calls: list[_VerifyCall] = []

    def cache_control(session: object, *, cache: object) -> object:
        wrapped_session = object()
        cachecontrol_calls.append(_CacheControlCall(cache, session, wrapped_session))
        return wrapped_session

    class FakeRequest(_FakeRequest):
        def __init__(self, *, session: object | None = None) -> None:
            super().__init__(session)
            request_instances.append(self)

    def verify_oauth2_token(
        presented: str, request: object, *, clock_skew_in_seconds: int
    ) -> Mapping[str, object]:
        assert callable(request)
        verify_calls.append(_VerifyCall(clock_skew_in_seconds, presented))
        return behavior(presented)

    cachecontrol_module = SimpleNamespace(CacheControl=cache_control)
    cache_module = SimpleNamespace(DictCache=_FakeDictCache)
    exceptions_module = SimpleNamespace(
        GoogleAuthError=_GoogleAuthError,
        TransportError=_TransportError,
    )
    id_token_module = SimpleNamespace(verify_oauth2_token=verify_oauth2_token)
    transport_module = SimpleNamespace(Request=FakeRequest)
    modules: dict[str, object] = {
        'cachecontrol': cachecontrol_module,
        'cachecontrol.cache': cache_module,
        'google.auth.exceptions': exceptions_module,
        'google.auth.transport.requests': transport_module,
        'google.oauth2.id_token': id_token_module,
    }
    return _StubModules(cachecontrol_calls, modules, request_instances, verify_calls)


def _install_stub_modules(monkeypatch: pytest.MonkeyPatch, stubs: _StubModules) -> None:

    def import_module(name: str) -> object:
        if name == 'jwt.exceptions':
            raise ImportError(name)
        return stubs.modules[name]

    monkeypatch.setattr(
        _googleverify.importlib,
        'import_module',
        import_module,
    )


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    with pytest.raises(RuntimeError) as caught:
        google_auth_verifier()('unused-token')
    assert caught.value.__suppress_context__
    assert 'Google certificate request could not be sent' in str(caught.value)
    assert str(missing) in str(caught.value)


@pytest.mark.parametrize('key_set', ['x509', 'jwks'])
def test_mixed_certificate_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, key_set: str
) -> None:
    cert, key = write_tls_material(tmp_path)
    claims = {'iss': 'https://accounts.google.com', 'iat': 0, 'exp': 2**62, 'sub': 'verified'}
    if key_set == 'x509':
        unsupported = (
            Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pem = rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        document = {
            'other': unsupported.decode(),
            'rsa': rsa_pem.decode(),
            'known': cert.read_text(),
            'invalid': 'broken',
        }
    else:
        valid = json.loads(
            jwt.get_algorithm_by_name('ES256').to_jwk(
                x509.load_pem_x509_certificate(cert.read_bytes()).public_key()
            )
        )
        document = {
            'keys': [
                {'kid': 'other', 'kty': 'unsupported'},
                {'kid': 'invalid', 'kty': 'EC', 'alg': 'none'},
                {**valid, 'kid': 'known'},
            ]
        }
    response = Mock(status=200, data=json.dumps(document).encode())
    requests_seen: list[google_transport.Request] = []

    def fetch(request: google_transport.Request, *_args: object, **_kwargs: object) -> Mock:
        requests_seen.append(request)
        return response

    monkeypatch.setattr(google_transport.Request, '__call__', fetch)
    verify = google_auth_verifier()

    def signed(kid: str) -> str:
        return jwt.encode(claims, key.read_bytes(), algorithm='ES256', headers={'kid': kid})

    assert verify(signed('known')) == claims
    if key_set == 'x509':
        assert verify(jwt.encode(claims, key.read_bytes(), algorithm='ES256')) == claims
    with pytest.raises(ValueError, match='Google identity token verification failed'):
        verify(signed('unknown'))
    with pytest.raises(RuntimeError, match='Google certificate'):
        verify(signed('other'))
    assert len(requests_seen) >= 3
    assert all(request is requests_seen[0] for request in requests_seen)


def test_unsupported_certificate_key_is_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    public_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    response = Mock(status=200, data=json.dumps({'known': public_key.decode()}).encode())
    monkeypatch.setattr(google_transport.Request, '__call__', Mock(return_value=response))
    with pytest.raises(RuntimeError, match='Google certificate'):
        google_auth_verifier()('presented')


def test_x509_verification_with_partial_jwt_module(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = write_tls_material(tmp_path)
    claims = {'iss': 'https://accounts.google.com', 'iat': 0, 'exp': 2**62, 'sub': 'verified'}
    token = jwt.encode(claims, key.read_bytes(), algorithm='ES256', headers={'kid': 'known'})
    response = Mock(status=200, data=json.dumps({'known': cert.read_text()}).encode())
    monkeypatch.setattr(google_transport.Request, '__call__', Mock(return_value=response))
    real_import = _googleverify.importlib.import_module

    def partial_jwt(name: str) -> object:
        if name == 'jwt.exceptions':
            return SimpleNamespace(InvalidTokenError=ValueError)
        return real_import(name)

    monkeypatch.setattr(_googleverify.importlib, 'import_module', partial_jwt)
    assert google_auth_verifier()(token) == claims
