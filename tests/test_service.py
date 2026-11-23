import datetime
import hashlib
import json
import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from unittest.mock import Mock

import pytest

from sg_token_broker import _secrets, _service
from sg_token_broker._admission import WaitingShare
from sg_token_broker._audit import AuditLogger
from sg_token_broker._config import BrokerConfig, ScopeConfig, load_config
from sg_token_broker._service import (
    _REST_TYPE,
    _SESSION_TYPE,
    BadRequestError,
    BrokerError,
    BrokerService,
    InvalidClientError,
    TokenRequest,
    _ForbiddenError,
    _IssuedToken,
    _RateLimitedError,
)
from sg_token_broker._sg import MintedToken, SGError, SGInvalidResponseError, SGMinter
from tests.conftest import BROKER_CREDENTIAL, BROKER_HASH

_AUDIT_INVALID = 'invalid'
_MASTER = 'masterkey'
_ROTATED_CREDENTIAL = 'replacement-credential'
_ROTATED_HASH = (
    'scrypt$16384$8$1$xD4dtY16Vi0z9FjGaQncTg==$'
    'bLsYeCxONHzlxQ8a08xa6VUoSF1A4IDm2+vbuxebBc/YSV4UmqUOkG9o1qW9kwS7uUQ57V7PVfd/NJijJ+9kXw=='
)
_SCRIPT = 'broker_read_all'
_WEIRD_TYPE = 'weird'


class TestIssueToken:
    def test_authenticated_cache_hit_completes_while_waiting_share_is_full(
        self, config: BrokerConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        waiting = WaitingShare(1)
        monkeypatch.setattr(_service, 'WaitingShare', Mock(return_value=waiting))
        minter = _FakeMinter()
        service = _make_service(config, minter)
        cached = service.issue_token(_request())
        entered, release = threading.Event(), threading.Event()

        def hold_rest(script_name: str, script_key: str) -> MintedToken:
            entered.set()
            release.wait()
            return _FakeMinter.mint_rest_token(minter, script_name, script_key)

        monkeypatch.setattr(minter, 'mint_rest_token', hold_rest)
        rest = _request(token_type=_REST_TYPE)
        with ThreadPoolExecutor(max_workers=1) as pool:
            owner = pool.submit(service.issue_token, rest)
            try:
                owner.add_done_callback(lambda _: entered.set())
                entered.wait()
                if owner.done():
                    owner.result()
                    pytest.fail('owner exited before its mint was released')
                assert not waiting.try_enter()
                with pytest.raises(_service._ServerBusyError) as busy:
                    service.issue_token(rest)
                assert busy.value.retry_after == pytest.approx(1)
                assert service.issue_token(_request()) == cached
            finally:
                release.set()
            assert owner.result().token_type == _REST_TYPE

    def test_bad_secret_rejected(
        self, config: BrokerConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wrong = BROKER_CREDENTIAL[:-1]
        verify = Mock(wraps=_secrets.verify_secret)
        monkeypatch.setattr(_secrets, 'verify_secret', verify)
        with pytest.raises(InvalidClientError):
            _make_service(config, _FakeMinter()).issue_token(_request(client_secret=wrong))
        verify.assert_called_once_with(wrong, BROKER_HASH)

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
        desktop = replace(config.clients['farm'], client_id='desktop', rate_limit_per_minute=20)
        expanded = replace(
            config,
            scopes=MappingProxyType(scopes),
            clients=MappingProxyType({'farm': farm, 'desktop': desktop}),
        )

        class DistinguishableMinter(_FakeMinter):
            rest_calls: int
            session_calls: int

            def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
                del script_key
                self.rest_calls += 1
                return MintedToken(token=f'rest-{self.rest_calls}-{script_name}', expires_in=600)

            def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
                del script_key
                self.session_calls += 1
                return MintedToken(
                    token=f'session-{self.session_calls}-{script_name}',
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
        assert (minter.session_calls, minter.rest_calls) == (3, 1)

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
        # First 16 hex digits of SHA-256 for sess-broker_read_all-masterkey.
        expected_fingerprint = '4bfe4b7204dd196b'
        assert issue['token_fp'] == expected_fingerprint
        assert all(issued.token not in m for m in messages)

    def test_issues_rest_token(self, config: BrokerConfig) -> None:
        issued = _make_service(config, _FakeMinter()).issue_token(_request(token_type=_REST_TYPE))
        assert issued.token == f'rest-{_SCRIPT}-{_MASTER}'

    def test_issues_session_token(
        self, config: BrokerConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base = datetime.datetime(2026, 8, 10, tzinfo=datetime.UTC)
        elapsed = 0
        monkeypatch.setattr(
            _service, '_utcnow', lambda: base + datetime.timedelta(seconds=elapsed)
        )
        minter = _FakeMinter()
        service = _make_service(
            replace(config, session_ttl_seconds=173), minter, clock=lambda: elapsed
        )
        issued = service.issue_token(_request())
        assert issued.token == f'sess-{_SCRIPT}-{_MASTER}'
        assert issued.token_type == _SESSION_TYPE
        assert issued.scope == 'read_all'
        assert issued.site_url == 'https://studio.shotgunstudio.com'
        assert issued.expires_at == base + datetime.timedelta(seconds=173)
        elapsed = 172
        assert service.issue_token(_request()) == issued
        assert minter.session_calls == 1
        elapsed = 173
        renewed = service.issue_token(_request())
        assert renewed.expires_at == base + datetime.timedelta(seconds=346)
        assert minter.session_calls == 2

    @pytest.mark.parametrize('primed', [False, True], ids=['cold', 'cached'])
    def test_only_the_served_replacement_is_audited_and_replay_is_free(
        self,
        *,
        primed: bool,
        config: BrokerConfig,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        old = MintedToken('first-token-value', None)
        fresh = MintedToken('fresh-token-value', None)
        minter = _FakeMinter()
        mints = [old, old, fresh] if primed else [old, fresh]
        mint = Mock(side_effect=mints)
        farm = replace(config.clients['farm'], rate_limit_per_minute=len(mints))
        config = replace(config, clients=MappingProxyType({**config.clients, 'farm': farm}))
        monkeypatch.setattr(minter, 'mint_session_token', mint)
        service = _make_service(config, minter)
        request = _request()
        report = replace(
            request, rejected_digests=frozenset({hashlib.sha256(old.token.encode()).hexdigest()})
        )
        with caplog.at_level(logging.INFO, logger='svc-test'):
            if primed:
                assert service.issue_token(request).token == old.token
            assert service.issue_token(report).token == fresh.token
            assert service.issue_token(report).token == fresh.token
        assert mint.call_count == len(mints)
        with pytest.raises(_RateLimitedError):
            service.issue_token(replace(request, token_type=_REST_TYPE))
        events = [json.loads(message) for message in caplog.messages]
        if primed:
            first = events.pop(0)
            assert (first['event'], first['cache'], first['outcome']) == (
                'issue',
                'miss',
                'minted',
            )
            assert 'replaced' not in first
        assert [(event['event'], event['cache'], event['outcome']) for event in events] == [
            ('issue', 'miss', 'replaced'),
            ('issue', 'hit', 'hit'),
        ]
        assert events[0]['replaced'] is True
        assert 'replaced' not in events[1]
        assert old.token not in caplog.text
        assert fresh.token not in caplog.text

    def test_rest_cache_never_outlives_token(
        self,
        config: BrokerConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        minter = _FakeMinter()
        minter.rest_expires_in = 61
        service = _make_service(config, minter)
        base = datetime.datetime(2026, 8, 10, 12, 0, tzinfo=datetime.UTC)
        now = [base]
        monkeypatch.setattr(_service, '_utcnow', lambda: now[0])

        first = service.issue_token(_request(token_type=_REST_TYPE))
        now[0] = base + datetime.timedelta(seconds=1)
        second = service.issue_token(_request(token_type=_REST_TYPE))

        assert first.expires_at == base + datetime.timedelta(seconds=1)
        assert second.expires_at == now[0] + datetime.timedelta(seconds=1)
        assert minter.rest_calls == 2

    def test_rotation_shares_cache_and_audits_the_matching_credential(
        self, rotating_config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        minter = _FakeMinter()
        service = _make_service(rotating_config, minter)
        failing_minter = _FakeMinter()
        failing_minter.fail = True
        failing_service = _make_service(rotating_config, failing_minter)
        credentials = rotating_config.clients['rotating'].credential_ids
        for secret, credential in zip(
            (BROKER_CREDENTIAL, _ROTATED_CREDENTIAL), credentials, strict=True
        ):
            caplog.clear()
            request = _request(client_id='rotating', client_secret=secret)
            with caplog.at_level(logging.INFO, logger='svc-test'):
                service.issue_token(request)
                with pytest.raises(_ForbiddenError):
                    service.issue_token(replace(request, scope='forbidden'))
                with pytest.raises(BrokerError) as caught:
                    failing_service.issue_token(request)
            assert caught.value.error == 'upstream_unavailable'
            events = [json.loads(message) for message in caplog.messages]
            assert [(event['event'], event['credential']) for event in events] == [
                ('issue', credential),
                ('deny', credential),
                ('error', credential),
            ]
            for sensitive in (BROKER_HASH, _ROTATED_HASH, BROKER_CREDENTIAL, _ROTATED_CREDENTIAL):
                assert sensitive not in caplog.text
        assert minter.session_calls == 1

    def test_scope_not_allowed_rejected(self, config: BrokerConfig) -> None:
        with pytest.raises(_ForbiddenError):
            _make_service(config, _FakeMinter()).issue_token(_request(scope='write_production'))

    def test_token_type_not_allowed_for_client_rejected(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        rest_only = replace(config.clients['farm'], token_types=frozenset({_REST_TYPE}))
        minter = _FakeMinter()
        service = _make_service(
            replace(config, clients=MappingProxyType({'farm': rest_only})), minter
        )
        with (
            caplog.at_level(logging.INFO, logger='svc-test'),
            pytest.raises(_ForbiddenError, match='token_type'),
        ):
            service.issue_token(_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert (record['reason'], record['token_type']) == ('forbidden', _SESSION_TYPE)
        assert minter.session_calls == 0
        assert service.issue_token(_request(token_type=_REST_TYPE)).token_type == _REST_TYPE

    def test_two_credentials_share_one_mint_budget(
        self, rotating_config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        clients = dict(rotating_config.clients)
        clients['rotating'] = replace(clients['rotating'], rate_limit_per_minute=1)
        minter = _FakeMinter()
        service = _make_service(replace(rotating_config, clients=clients), minter)
        request = _request(client_id='rotating')
        rotated = replace(request, client_secret=_ROTATED_CREDENTIAL)
        with caplog.at_level(logging.INFO, logger='svc-test'):
            assert service.issue_token(request) == service.issue_token(rotated)
            with pytest.raises(_RateLimitedError) as caught:
                service.issue_token(replace(rotated, token_type=_REST_TYPE))
        assert caught.value.retry_after == pytest.approx(60)
        issues = [json.loads(message) for message in caplog.messages]
        assert [(issue['cache'], issue['outcome']) for issue in issues[:2]] == [
            ('miss', 'minted'),
            ('hit', 'hit'),
        ]
        assert (minter.session_calls, minter.rest_calls) == (1, 0)

    def test_unknown_client_id_is_bounded_in_audit(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        huge = 'A' * 48000
        with (
            caplog.at_level(logging.INFO, logger='svc-test'),
            pytest.raises(InvalidClientError),
        ):
            _make_service(config, _FakeMinter()).issue_token(
                _request(client_id=huge, scope='not-a-scope', token_type=_WEIRD_TYPE)
            )
        record = json.loads(caplog.records[-1].getMessage())
        assert len(record['client_id']) == 64
        assert record['client_id_truncated'] is True
        assert record['scope'] == _AUDIT_INVALID
        assert record['token_type'] == _AUDIT_INVALID
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
        farm = replace(config.clients['farm'], rate_limit_per_minute=1)
        service = _make_service(replace(config, clients={'farm': farm}), _FakeMinter())
        with (
            caplog.at_level(logging.INFO, logger='svc-test'),
            pytest.raises(BrokerError) as excinfo,
        ):
            service.issue_token(_request())
        assert excinfo.value.status == 500
        assert excinfo.value.error == 'internal_error'
        assert str(excinfo.value) == 'internal error'
        assert 'SGTB_KEY_READ_ALL' not in str(excinfo.value)
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['reason'] == 'internal_error'
        assert record['detail'] == 'environment variable SGTB_KEY_READ_ALL is not set or empty'
        monkeypatch.setenv('SGTB_KEY_READ_ALL', _MASTER)
        assert service.issue_token(_request()).token_type == _SESSION_TYPE

    def test_upstream_error_audit_carries_the_cause(
        self, config: BrokerConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        minter = _FakeMinter()
        minter.fail = True
        with (
            caplog.at_level(logging.INFO, logger='svc-test'),
            pytest.raises(BrokerError) as caught,
        ):
            _make_service(config, minter).issue_token(_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert caught.value.status == 503
        assert record['reason'] == 'upstream_unavailable'
        assert record['detail'] == 'upstream down'

    @pytest.mark.parametrize('client_id', ['rotating', 'farm', 'unknown'])
    def test_wrong_secret_checks_two_hashes_and_omits_audit_credential(
        self,
        rotating_config: BrokerConfig,
        client_id: str,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        service = _make_service(rotating_config, _FakeMinter())
        verify = Mock(wraps=_secrets.verify_secret)
        monkeypatch.setattr(_secrets, 'verify_secret', verify)
        # Even a match against a padding hash must still fail authentication.
        wrong = 'timing-equalizer'
        with caplog.at_level(logging.INFO, logger='svc-test'), pytest.raises(InvalidClientError):
            service.issue_token(_request(client_id=client_id, client_secret=wrong))
        assert verify.call_count == 2
        event = json.loads(caplog.messages[-1])
        assert event['event'] == 'deny'
        assert 'credential' not in event
        assert wrong not in caplog.text
        assert BROKER_HASH not in caplog.text
        assert _ROTATED_HASH not in caplog.text


class TestSecretRepr:
    def test_issued_token_repr_hides_the_token(self) -> None:
        value = 'secret-token-value'
        issued = _IssuedToken(
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
        assert BROKER_CREDENTIAL not in repr(token_request)
        assert BROKER_CREDENTIAL not in str(token_request)


class _FakeMinter:
    def __init__(self) -> None:
        self.session_calls = 0
        self.rest_calls = 0
        self.rest_expires_in = 600
        self.fail = False

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        self.rest_calls += 1
        return MintedToken(
            token=f'rest-{script_name}-{script_key}', expires_in=self.rest_expires_in
        )

    def mint_session_token(self, script_name: str, script_key: str) -> MintedToken:
        self.session_calls += 1
        if self.fail:
            raise SGError('upstream down')
        return MintedToken(token=f'sess-{script_name}-{script_key}', expires_in=None)


def _request(
    *,
    client_id: str = 'farm',
    client_secret: str = BROKER_CREDENTIAL,
    scope: str = 'read_all',
    token_type: str = _SESSION_TYPE,
) -> TokenRequest:
    return TokenRequest(
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        token_type=token_type,
        source_ip='10.0.0.9',
    )


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv('SGTB_KEY_READ_ALL', _MASTER)
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
    secret_hash: "{BROKER_HASH}"
    scopes: [read_all]
""")
    return path


@pytest.fixture
def config(config_path: Path) -> BrokerConfig:
    return load_config(config_path)


def _make_service(
    config: BrokerConfig,
    minter: _FakeMinter | SGMinter,
    *,
    clock: Callable[[], float] = lambda: 0.0,
) -> BrokerService:
    return BrokerService(
        config=config,
        minter=minter,
        clock=clock,
        audit=AuditLogger(logging.getLogger('svc-test')),
    )


@pytest.fixture
def rotating_config(config_path: Path) -> BrokerConfig:
    with config_path.open('a') as stream:
        stream.write(f"""
  rotating:
    secret_hashes: ["{BROKER_HASH}", "{_ROTATED_HASH}"]
    scopes: [read_all]
    rate_limit_per_minute: 10
""")
    return load_config(config_path)


@pytest.mark.parametrize('expires_in', [1, 30, 60])
def test_rest_lifetime_within_margin_is_refused(config: BrokerConfig, expires_in: int) -> None:
    minter = _FakeMinter()
    minter.rest_expires_in = expires_in
    with pytest.raises(_service._InvalidUpstreamResponseError) as caught:
        _make_service(config, minter).issue_token(_request(token_type=_REST_TYPE))
    assert isinstance(caught.value.__cause__, SGInvalidResponseError)
    assert str(caught.value.__cause__) == 'SG token lifetime too short to serve'


def test_upstream_refusal_audit_keeps_only_operation_and_codes(
    config: BrokerConfig, caplog: pytest.LogCaptureFixture
) -> None:
    fault = {
        'exception': True,
        'message': f'refused {_MASTER} {BROKER_CREDENTIAL} private-provider-marker',
        'error_code': 102,
    }
    session = Mock(post=Mock(return_value=Mock(status_code=200, json=Mock(return_value=fault))))
    service = _make_service(config, SGMinter(config.site_url, session=session))
    with caplog.at_level(logging.INFO, logger='svc-test'), pytest.raises(BrokerError):
        service.issue_token(_request())
    detail = json.loads(caplog.records[-1].getMessage())['detail']
    assert 'session token request' in detail
    assert 'HTTP 200' in detail
    assert 'RPC 102' in detail
    assert _MASTER not in caplog.text
    assert BROKER_CREDENTIAL not in caplog.text
    assert 'private-provider-marker' not in caplog.text
    assert 'check the SG script name and key' in detail
