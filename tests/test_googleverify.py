from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
import requests

from sg_token_broker import _googleverify
from sg_token_broker._googleverify import VerifierUnavailableError, google_auth_verifier


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
        assert all(call.request is stubs.request_instances[0] for call in stubs.verify_calls)
        assert all(call.clock_skew_in_seconds == 10 for call in stubs.verify_calls)

    def test_transport_errors_propagate_unwrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        error = _TransportError('cert fetch failed')

        def raise_transport_error(presented: str) -> Mapping[str, object]:
            del presented
            raise error

        stubs = _build_stub_modules(raise_transport_error)
        _install_stub_modules(monkeypatch, stubs)

        verify = google_auth_verifier()
        with pytest.raises(_TransportError) as caught:
            verify('whatever-value')
        assert caught.value is error

    def test_wraps_google_auth_errors_as_value_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        def reject(presented: str) -> Mapping[str, object]:
            del presented
            raise _GoogleAuthError('Wrong issuer.')

        stubs = _build_stub_modules(reject)
        _install_stub_modules(monkeypatch, stubs)

        verify = google_auth_verifier()
        with pytest.raises(ValueError, match='Wrong issuer'):
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
    request: object


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
        verify_calls.append(_VerifyCall(clock_skew_in_seconds, presented, request))
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
        return stubs.modules[name]

    monkeypatch.setattr(
        _googleverify.importlib,
        'import_module',
        import_module,
    )
