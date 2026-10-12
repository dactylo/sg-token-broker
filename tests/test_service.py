import datetime
import json
import logging
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest

from sg_token_broker import _service
from sg_token_broker._audit import AuditLogger
from sg_token_broker._cache import TTLCache
from sg_token_broker._config import BrokerConfig, ClientConfig, ScopeConfig, load_config
from sg_token_broker._secrets import token_fingerprint
from sg_token_broker._service import (
    _REST_TYPE,
    _SESSION_TYPE,
    BadRequestError,
    BrokerError,
    BrokerService,
    InvalidClientError,
    IssuedToken,
    TokenRequest,
    _ForbiddenError,
    _RateLimitedError,
    _UpstreamError,
)
from sg_token_broker._sg import MintedToken, SGError

AUDIT_INVALID = 'invalid'
FARM_CREDENTIAL = 'farm-credential'
# Precomputed hash of FARM_CREDENTIAL; authentication still uses the real KDF.
_FARM_HASH = (
    'scrypt$16384$8$1$tcz9OTN0w9hLf2Zh12rdKQ==$'
    'awBt8momr/VzxYTd7/N+PmovkQUbLjh48W5GCf/2yUlprwvi/nWejmNmwCWgsPo5wy/dsyY/b6t/DCDF6l1C3Q=='
)
MASTER = 'masterkey'
SCRIPT = 'broker_read_all'
WEIRD_TYPE = 'weird'


class TestIssueToken:
    def test_bad_secret_rejected(self, config: BrokerConfig) -> None:
        wrong = FARM_CREDENTIAL[:-1]
        with pytest.raises(InvalidClientError):
            _make_service(config, _FakeMinter()).issue_token(_request(client_secret=wrong))

    def test_bad_token_type_rejected(self, config: BrokerConfig) -> None:
        bogus_type = 'jwt'
        with pytest.raises(BadRequestError):
            _make_service(config, _FakeMinter()).issue_token(_request(token_type=bogus_type))

    def test_cache_hit_preserves_expires_at(
        self, config: BrokerConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service = _make_service(config, _FakeMinter())
        base = datetime.datetime(2026, 7, 10, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_service, '_utcnow', lambda: base)
        first = service.issue_token(_request(token_type=_REST_TYPE))
        monkeypatch.setattr(_service, '_utcnow', lambda: base + datetime.timedelta(seconds=45))
        second = service.issue_token(_request(token_type=_REST_TYPE))
        assert second.token == first.token
        assert second.expires_at == first.expires_at
        assert first.expires_at == base + datetime.timedelta(seconds=600 - 60)

    def test_cache_isolated_by_client_scope_and_token_type(
        self, config: BrokerConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('SGTB_KEY_WRITE_NOTES', 'write-key')
        scopes = dict(config.scopes)
        scopes['write_notes'] = ScopeConfig(
            script_name='broker_write_notes',
            script_key_env='SGTB_KEY_WRITE_NOTES',
            script_key_file=None,
        )
        farm = replace(
            config.clients['farm'],
            scopes=frozenset({'read_all', 'write_notes'}),
            rate_limit_per_minute=20,
        )
        desktop = ClientConfig(
            client_id='desktop',
            secret_hash=_FARM_HASH,
            scopes=frozenset({'read_all'}),
            rate_limit_per_minute=20,
        )
        expanded = replace(
            config,
            scopes=MappingProxyType(scopes),
            clients=MappingProxyType({'farm': farm, 'desktop': desktop}),
        )

        class DistinguishableMinter(_FakeMinter):
            _rest_calls: int
            _session_calls: int

            def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
                del script_key
                self._rest_calls += 1
                return MintedToken(token=f'rest-{self._rest_calls}-{script_name}', expires_in=600)

            def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
                del script_key
                self._session_calls += 1
                return MintedToken(
                    token=f'session-{self._session_calls}-{script_name}',
                    expires_in=None,
                )

        minter = DistinguishableMinter()
        service = _make_service(expanded, minter)
        farm_read = service.issue_token(_request())
        farm_read_again = service.issue_token(_request())
        desktop_read = service.issue_token(_request(client_id='desktop'))
        farm_write = service.issue_token(_request(scope='write_notes'))
        farm_rest = service.issue_token(_request(token_type=_REST_TYPE))

        assert farm_read.token == farm_read_again.token
        assert len({farm_read.token, desktop_read.token, farm_write.token, farm_rest.token}) == 4
        assert (minter._session_calls, minter._rest_calls) == (3, 1)

    def test_caller_fault_audit_has_no_detail(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='svc-test'), pytest.raises(BrokerError):
            _make_service(config, _FakeMinter()).issue_token(_request(token_type='A' * 1000))
        record = json.loads(caplog.records[-1].getMessage())
        assert 'detail' not in record
        assert len(caplog.records[-1].getMessage()) < 512

    def test_issue_audit_event_carries_token_fingerprint(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='svc-test'):
            issued = _make_service(config, _FakeMinter()).issue_token(_request())
        messages = [r.getMessage() for r in caplog.records]
        issue = next(json.loads(m) for m in messages if json.loads(m).get('event') == 'issue')
        assert issue['token_fp'] == token_fingerprint(issued.token)
        assert all(issued.token not in m for m in messages)

    def test_issues_rest_token(self, config: BrokerConfig) -> None:
        issued = _make_service(config, _FakeMinter()).issue_token(_request(token_type=_REST_TYPE))
        assert issued.token == f'rest-{SCRIPT}-{MASTER}'

    def test_issues_session_token(self, config: BrokerConfig) -> None:
        minter = _FakeMinter()
        issued = _make_service(config, minter).issue_token(_request())
        assert issued.token == f'sess-{SCRIPT}-{MASTER}'
        assert issued.token_type == _SESSION_TYPE
        assert issued.scope == 'read_all'
        assert issued.site_url == 'https://studio.shotgunstudio.com'
        assert issued.expires_at.tzinfo is not None

    def test_rate_limit(self, config: BrokerConfig) -> None:
        service = _make_service(config, _FakeMinter())
        for _ in range(3):
            service.issue_token(_request())
        with pytest.raises(_RateLimitedError):
            service.issue_token(_request())

    def test_rate_limiter_is_per_client_and_resets_at_the_window_boundary(self) -> None:
        now = [0.0]
        limiter = _service._RateLimiter(lambda: now[0])

        assert limiter._check('a', 2)
        assert limiter._check('a', 2)
        assert not limiter._check('a', 2)
        assert limiter._check('b', 2)
        now[0] = 59.999
        assert not limiter._check('a', 2)
        now[0] = 60.0
        assert limiter._check('a', 2)

    def test_rest_cache_never_outlives_token(
        self,
        config: BrokerConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        minter = _FakeMinter()
        minter._rest_expires_in = 90
        service = _make_service(config, minter)
        base = datetime.datetime(2026, 8, 10, 12, 0, tzinfo=datetime.UTC)
        now = [base]
        monkeypatch.setattr(_service, '_utcnow', lambda: now[0])

        first = service.issue_token(_request(token_type=_REST_TYPE))
        now[0] = base + datetime.timedelta(seconds=31)
        second = service.issue_token(_request(token_type=_REST_TYPE))

        assert first.expires_at == base + datetime.timedelta(seconds=30)
        assert second.expires_at == now[0] + datetime.timedelta(seconds=30)
        assert minter._rest_calls == 2

    def test_scope_not_allowed_rejected(self, config: BrokerConfig) -> None:
        with pytest.raises(_ForbiddenError):
            _make_service(config, _FakeMinter()).issue_token(_request(scope='write_production'))

    def test_unknown_client_id_is_bounded_in_audit(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        huge = 'A' * 48000
        with (
            caplog.at_level(logging.INFO, logger='svc-test'),
            pytest.raises(InvalidClientError),
        ):
            _make_service(config, _FakeMinter()).issue_token(
                _request(client_id=huge, scope='not-a-scope', token_type=WEIRD_TYPE)
            )
        record = json.loads(caplog.records[-1].getMessage())
        assert len(record['client_id']) == 64
        assert record['client_id_truncated'] is True
        assert record['scope'] == AUDIT_INVALID
        assert record['token_type'] == AUDIT_INVALID
        assert len(caplog.records[-1].getMessage()) < 512

    def test_unknown_client_rejected(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger='svc-test'), pytest.raises(InvalidClientError):
            _make_service(config, _FakeMinter()).issue_token(_request(client_id='ghost'))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['client_id'] == 'ghost'
        assert 'client_id_truncated' not in record

    def test_unresolvable_script_key_is_opaque_500(
        self,
        config: BrokerConfig,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv('SGTB_KEY_READ_ALL')
        service = _make_service(config, _FakeMinter())
        with (
            caplog.at_level(logging.INFO, logger='svc-test'),
            pytest.raises(BrokerError) as excinfo,
        ):
            service.issue_token(_request())
        assert excinfo.value.status == 500
        assert excinfo.value.error == 'internal_error'
        assert 'SGTB_KEY_READ_ALL' not in str(excinfo.value)
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['reason'] == 'internal_error'

    def test_upstream_error_audit_carries_the_cause(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        minter = _FakeMinter()
        minter._fail = True
        with caplog.at_level(logging.INFO, logger='svc-test'), pytest.raises(_UpstreamError):
            _make_service(config, minter).issue_token(_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['reason'] == 'upstream_error'
        assert record['detail'] == 'upstream down'


class TestSecretRepr:
    def test_issued_token_repr_hides_the_token(self) -> None:
        value = 'secret-token-value'
        issued = IssuedToken(
            token=value,
            token_type=_SESSION_TYPE,
            scope='read_all',
            site_url='https://studio.example.com',
            expires_at=datetime.datetime(2026, 7, 10, tzinfo=datetime.UTC),
        )
        assert value not in repr(issued)
        assert value not in str(issued)

    def test_token_request_repr_hides_the_client_secret(self) -> None:
        token_request = _request()
        assert FARM_CREDENTIAL not in repr(token_request)
        assert FARM_CREDENTIAL not in str(token_request)


class _FakeMinter:
    def __init__(self) -> None:
        self._session_calls = 0
        self._rest_calls = 0
        self._rest_expires_in = 600
        self._fail = False

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        self._rest_calls += 1
        return MintedToken(
            token=f'rest-{script_name}-{script_key}', expires_in=self._rest_expires_in
        )

    def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
        self._session_calls += 1
        if self._fail:
            raise SGError('upstream down')
        return MintedToken(token=f'sess-{script_name}-{script_key}', expires_in=None)


def _request(**overrides: str) -> TokenRequest:
    base: dict[str, str] = {
        'client_id': 'farm',
        'client_secret': FARM_CREDENTIAL,
        'scope': 'read_all',
        'token_type': 'session',
        'source_ip': '10.0.0.9',
    }
    base.update(overrides)
    return TokenRequest(**base)


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BrokerConfig:
    monkeypatch.setenv('SGTB_KEY_READ_ALL', MASTER)
    path = tmp_path / 'broker.yml'
    path.write_text(f"""
site_url: https://studio.shotgunstudio.com
defaults:
  session_ttl_seconds: 600
  rate_limit_per_minute: 3
scopes:
  read_all:
    script_name: broker_read_all
    script_key_env: SGTB_KEY_READ_ALL
clients:
  farm:
    secret_hash: "{_FARM_HASH}"
    scopes: [read_all]
""")
    return load_config(path)


def _make_service(config: BrokerConfig, minter: _FakeMinter) -> BrokerService:
    return BrokerService(
        config=config,
        minter=minter,
        cache=TTLCache(),
        audit=AuditLogger(logging.getLogger('svc-test')),
    )
