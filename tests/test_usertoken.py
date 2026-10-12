import datetime
import json
import logging
from collections.abc import Mapping

import pytest

from sg_token_broker import _usertoken
from sg_token_broker._audit import AuditLogger
from sg_token_broker._gclaims import ClaimsValidator, Verifier
from sg_token_broker._secrets import token_fingerprint
from sg_token_broker._sg import SGError, SGMinter
from sg_token_broker._users import UserDirectory
from sg_token_broker._usertoken import (
    _REST_TYPE,
    ServiceAccount,
    UserTokenError,
    UserTokenRequest,
    UserTokenService,
    _BadRequestError,
    _ForbiddenError,
    _UnauthorizedError,
    _UpstreamError,
)
from tests.conftest import _FakeSG

AUDIENCE = 'client-id-123.apps.googleusercontent.com'

AUDIT_INVALID = 'invalid'
AUDIT_LOGGER = 'test-usertoken-audit'
BOGUS_TYPE = 'bogus'
DOMAIN = 'studio.example'
EMAIL = 'jane.exec@studio.example'
LOGIN = 'jane.exec'
SESSION_TYPES = frozenset({'session'})
SESSION_TYPE = next(iter(SESSION_TYPES))
UNKNOWN_TYPE = 'bearer'


class TestIssueToken:
    def test_bad_identity_token_is_unauthorized(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER), pytest.raises(_UnauthorizedError):
            _make_service(fake_sg).issue_token(_make_request('forged', token_type=BOGUS_TYPE))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'deny'
        assert record['reason'] == 'unauthorized'
        assert record['token_type'] == AUDIT_INVALID

    def test_cache_hit_preserves_expires_at(
        self, fake_sg: _FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        service = _make_service(fake_sg)
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base)
        first = service.issue_token(_make_request())
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base + datetime.timedelta(seconds=60))
        second = service.issue_token(_make_request())
        assert second.token == first.token
        assert second.expires_at == first.expires_at

    def test_denials_are_not_cached(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._disabled_login = LOGIN
        service = _make_service(fake_sg)
        with pytest.raises(_ForbiddenError):
            service.issue_token(_make_request())
        fake_sg._disabled_login = ''
        assert service.issue_token(_make_request()).login == LOGIN

    def test_expires_at_is_sg_lifetime_minus_margin(
        self, fake_sg: _FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base)
        issued = _make_service(fake_sg).issue_token(_make_request())
        assert issued.expires_at == base + datetime.timedelta(seconds=600 - 30)

    def test_issues_user_bound_token(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        service = _make_service(fake_sg)
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER):
            issued = service.issue_token(_make_request())
        assert issued.token == f'rest-sudo_as_login:{LOGIN}'
        assert issued.token_type == _REST_TYPE
        assert issued.login == LOGIN
        assert issued.site_url == fake_sg._url
        assert fake_sg._rest_scopes == [f'sudo_as_login:{LOGIN}']
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'issue'
        assert record['email'] == EMAIL
        assert record['login'] == LOGIN
        assert record['aud'] == AUDIENCE
        assert record['token_fp'] == token_fingerprint(issued.token)
        assert issued.token not in caplog.text

    def test_logins_do_not_share_cache(self, fake_sg: _FakeSG) -> None:
        other_email = 'sam.ops@studio.example'
        other_login = 'sam.ops'
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._known_emails[other_email] = other_login
        service = _make_service(fake_sg)
        first = service.issue_token(_make_request())
        second = service.issue_token(_make_request(other_email))
        assert first.token == f'rest-sudo_as_login:{LOGIN}'
        assert second.token == f'rest-sudo_as_login:{other_login}'
        assert fake_sg._rest_scopes == [f'sudo_as_login:{LOGIN}', f'sudo_as_login:{other_login}']

    def test_sg_failure_is_upstream_error(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._fail_user_lookup = True
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER), pytest.raises(_UpstreamError):
            _make_service(fake_sg).issue_token(_make_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['reason'] == 'upstream_error'

    def test_short_sg_lifetime_is_upstream_error(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._rest_expires_in = 120
        with pytest.raises(_UpstreamError):
            _make_service(fake_sg).issue_token(_make_request())

    def test_sudo_mint_5xx_is_upstream_error(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._fail_rest = True
        fake_sg._rest_failure_status = 503
        with pytest.raises(_UpstreamError):
            _make_service(fake_sg).issue_token(_make_request())

    def test_sudo_mint_fails_closed_when_sg_rejects_the_service_key(
        self, fake_sg: _FakeSG
    ) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        service = _make_service(fake_sg)
        fake_sg._rest_credentials = {'usersvc': 'not-the-configured-key'}
        with pytest.raises(UserTokenError) as excinfo:
            service.issue_token(_make_request(token_type=_REST_TYPE))
        assert excinfo.value.status == 502

    def test_token_is_cached_per_login(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        service = _make_service(fake_sg)
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER):
            first = service.issue_token(_make_request())
            miss = json.loads(caplog.records[-1].getMessage())
            second = service.issue_token(_make_request())
        hit = json.loads(caplog.records[-1].getMessage())
        assert first.token == second.token
        assert fake_sg._rest_scopes == [f'sudo_as_login:{LOGIN}']
        assert miss['cache'] == 'miss'
        assert hit['cache'] == 'hit'

    def test_unknown_email_is_forbidden(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER), pytest.raises(_ForbiddenError):
            _make_service(fake_sg).issue_token(_make_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'deny'
        assert record['email'] == EMAIL
        assert record['reason'] == 'forbidden'

    def test_unknown_type_audit_is_bounded_after_claims(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        huge = 'B' * 48000
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER), pytest.raises(_BadRequestError):
            _make_service(fake_sg).issue_token(_make_request(token_type=huge))
        message = caplog.records[-1].getMessage()
        record = json.loads(message)
        assert record['token_type'] == AUDIT_INVALID
        assert huge not in message
        assert len(message) < 512

    def test_wrong_domain_is_unauthorized(self, fake_sg: _FakeSG) -> None:
        with pytest.raises(_UnauthorizedError):
            _make_service(fake_sg).issue_token(_make_request('intruder@evil.example'))


def _email_verifier(presented: str) -> Mapping[str, object]:
    if '@' not in presented:
        raise ValueError('forged token')
    return {'aud': AUDIENCE, 'email': presented, 'email_verified': True, 'hd': DOMAIN}


def _enable_session_user(fake_sg: _FakeSG) -> None:
    fake_sg._known_emails[EMAIL] = LOGIN
    fake_sg._human_logins[LOGIN] = 7
    fake_sg._rpc_unique_human_sessions = True


def _make_request(
    email: str = EMAIL, token_type: str = _REST_TYPE, refresh: bool = False
) -> UserTokenRequest:
    return UserTokenRequest(
        authorization=f'Bearer {email}',
        source_ip='198.51.100.7',
        request_id='req1',
        token_type=token_type,
        refresh=refresh,
    )


def _make_service(
    fake_sg: _FakeSG,
    verifier: Verifier = _email_verifier,
    token_types: frozenset[str] = frozenset({'rest'}),
) -> UserTokenService:
    fake_sg._rest_credentials = {'usersvc': 'svc-credential'}
    minter = SGMinter(fake_sg._url)
    return UserTokenService(
        ServiceAccount(fake_sg._url, 'usersvc', 'svc-credential'),
        ClaimsValidator(verifier, [AUDIENCE], DOMAIN),
        UserDirectory(fake_sg._url, minter, 'usersvc', 'svc-credential'),
        minter,
        AuditLogger(logging.getLogger(AUDIT_LOGGER)),
        token_types=token_types,
    )


class TestSessionIssuance:
    def test_audit_records_token_type(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=SESSION_TYPES)
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER):
            service.issue_token(_make_request(token_type=SESSION_TYPE))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['token_type'] == SESSION_TYPE

    @pytest.mark.parametrize('kind', [_REST_TYPE, SESSION_TYPE])
    def test_audit_records_valid_token_type_on_unauthorized(
        self, fake_sg: _FakeSG, caplog: pytest.LogCaptureFixture, kind: str
    ) -> None:
        with (
            caplog.at_level(logging.INFO, logger=AUDIT_LOGGER),
            pytest.raises(_UnauthorizedError),
        ):
            _make_service(fake_sg).issue_token(_make_request('forged', token_type=kind))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['token_type'] == kind

    def test_disallowed_type_is_forbidden_before_minting(self, fake_sg: _FakeSG) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=frozenset({'rest'}))
        with pytest.raises(_ForbiddenError):
            service.issue_token(_make_request(token_type=SESSION_TYPE))
        assert _sudo_mint_count(fake_sg) == 0

    def test_force_refresh_keeps_live_session(self, fake_sg: _FakeSG) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=SESSION_TYPES)
        first = service.issue_token(_make_request(token_type=SESSION_TYPE))
        second = service.issue_token(_make_request(token_type=SESSION_TYPE, refresh=True))
        assert second.token == first.token
        assert _sudo_mint_count(fake_sg) == 1

    def test_force_refresh_replaces_dead_session(self, fake_sg: _FakeSG) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=SESSION_TYPES)
        first = service.issue_token(_make_request(token_type=SESSION_TYPE))
        fake_sg._disabled_human_sessions.add(first.token)
        second = service.issue_token(_make_request(token_type=SESSION_TYPE, refresh=True))
        assert second.token != first.token
        assert _sudo_mint_count(fake_sg) == 2

    def test_minter_fault_is_upstream_error(self, fake_sg: _FakeSG) -> None:
        _enable_session_user(fake_sg)
        fake_sg._rpc_sudo_mint_failures[('usersvc', LOGIN)] = {
            'exception': True,
            'message': "The script does not have permission to 'sudo': usersvc",
            'error_code': 102,
        }
        with pytest.raises(_UpstreamError):
            _make_service(fake_sg, token_types=SESSION_TYPES).issue_token(
                _make_request(token_type=SESSION_TYPE)
            )

    def test_rest_cache_until_equals_expires_at(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        issued = _make_service(fake_sg).issue_token(_make_request())
        assert issued.cache_until == issued.expires_at

    def test_rest_minter_sudo_fault_is_upstream(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._fail_rest = True
        fake_sg._rest_failure_status = 400
        fake_sg._rest_failure_title = "The script does not have permission to 'sudo': usersvc"
        with pytest.raises(_UpstreamError):
            _make_service(fake_sg).issue_token(_make_request())

    def test_rest_unrecognized_auth_failure_is_upstream(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._fail_rest = True
        fake_sg._rest_failure_status = 401
        with pytest.raises(_UpstreamError):
            _make_service(fake_sg).issue_token(_make_request())

    def test_rest_unrecognized_sudo_adjacent_title_is_upstream(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        fake_sg._fail_rest = True
        fake_sg._rest_failure_status = 400
        fake_sg._rest_failure_title = 'sudo subsystem unavailable'
        with pytest.raises(_UpstreamError):
            _make_service(fake_sg).issue_token(_make_request())

    @pytest.mark.parametrize(
        ('fault', 'display', 'status'),
        [
            ("Cannot 'sudo' - inactive user account", 'RPC authentication failed', 403),
            ("The script does not have permission to 'sudo'", "Cannot 'sudo'", 502),
            ('Authentication failed', "Cannot 'sudo'", 502),
        ],
    )
    def test_rpc_refusal_uses_fault_detail(
        self,
        fake_sg: _FakeSG,
        monkeypatch: pytest.MonkeyPatch,
        fault: str,
        display: str,
        status: int,
    ) -> None:
        _enable_session_user(fake_sg)
        fake_sg._rpc_sudo_mint_failures[('usersvc', LOGIN)] = {
            'exception': True,
            'message': fault,
            'error_code': 102,
        }

        def formatted_message(_self: SGError) -> str:
            return display

        monkeypatch.setattr(SGError, '__str__', formatted_message)
        with pytest.raises(UserTokenError) as excinfo:
            _make_service(fake_sg, token_types=SESSION_TYPES).issue_token(
                _make_request(token_type=SESSION_TYPE)
            )
        assert excinfo.value.status == status

    def test_session_cache_is_per_login_and_type(
        self, fake_sg: _FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=frozenset({'rest', 'session'}))
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base)
        first = service.issue_token(_make_request(token_type=SESSION_TYPE))
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base + datetime.timedelta(seconds=60))
        second = service.issue_token(_make_request(token_type=SESSION_TYPE))
        assert second.token == first.token
        assert second.cache_until == first.cache_until
        rest = service.issue_token(_make_request())
        assert rest.token != first.token

    def test_session_type_mints_sudo_session(self, fake_sg: _FakeSG) -> None:
        _enable_session_user(fake_sg)
        issued = _make_service(fake_sg, token_types=SESSION_TYPES).issue_token(
            _make_request(token_type=SESSION_TYPE)
        )
        assert issued.token_type == SESSION_TYPE
        assert issued.token.startswith('sess-sudo-mint-')
        assert issued.login == LOGIN
        assert issued.expires_at is None
        assert issued.cache_until > datetime.datetime.now(datetime.UTC)

    def test_target_refusal_is_forbidden(self, fake_sg: _FakeSG) -> None:
        _enable_session_user(fake_sg)
        fake_sg._rpc_sudo_mint_failures[('usersvc', LOGIN)] = {
            'exception': True,
            'message': "Cannot 'sudo' - inactive user account: 'jane.exec'",
            'error_code': 102,
        }
        with pytest.raises(_ForbiddenError):
            _make_service(fake_sg, token_types=SESSION_TYPES).issue_token(
                _make_request(token_type=SESSION_TYPE)
            )

    @pytest.mark.parametrize(
        ('kind', 'expected'),
        [
            (_REST_TYPE, _REST_TYPE),
            (SESSION_TYPE, SESSION_TYPE),
            (BOGUS_TYPE, AUDIT_INVALID),
        ],
    )
    def test_unhandled_audit_classifies_token_type(
        self,
        fake_sg: _FakeSG,
        caplog: pytest.LogCaptureFixture,
        kind: str,
        expected: str,
    ) -> None:
        service = _make_service(fake_sg)
        with caplog.at_level(logging.INFO, logger=AUDIT_LOGGER):
            service.log_unhandled(_make_request(token_type=kind), RuntimeError())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['token_type'] == expected

    def test_unknown_type_is_bad_request(self, fake_sg: _FakeSG) -> None:
        with pytest.raises(_BadRequestError):
            _make_service(fake_sg).issue_token(_make_request(token_type=UNKNOWN_TYPE))


def _sudo_mint_count(fake_sg: _FakeSG) -> int:
    return sum(
        1
        for entry in fake_sg._requests
        if entry['path'] == '/api3/json'
        and 'sudo_as_login' in str(entry['body'])
        and 'script_name' in str(entry['body'])
    )
