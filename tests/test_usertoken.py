import datetime
import json
import logging
import traceback
from collections.abc import Mapping
from unittest.mock import Mock
from urllib.parse import parse_qs

import pytest

from sg_token_broker import _usertoken
from sg_token_broker._audit import AuditLogger
from sg_token_broker._gclaims import ClaimsValidator, Verifier
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
)
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.conftest import FakeSG

_AUDIENCE = 'client-id-123.apps.googleusercontent.com'

_AUDIT_INVALID = 'invalid'
_AUDIT_LOGGER = 'test-usertoken-audit'
_BOGUS_TYPE = 'bogus'
_DOMAIN = 'studio.example'
_EMAIL = 'jane.exec@studio.example'
_LOGIN = 'jane.exec'
_SESSION_TYPES = frozenset({'session'})
_SESSION_TYPE = next(iter(_SESSION_TYPES))


class TestIssueToken:
    def test_bad_identity_token_is_unauthorized(
        self, offline_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        with (
            caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER),
            pytest.raises(_UnauthorizedError),
        ):
            _make_service(offline_sg).issue_token(_make_request('forged', token_type=_BOGUS_TYPE))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'deny'
        assert record['reason'] == 'unauthorized'
        assert record['token_type'] == _AUDIT_INVALID

    def test_cache_hit_preserves_expires_at(
        self, fake_sg: FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        service = _make_service(fake_sg)
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base)
        first = service.issue_token(_make_request())
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base + datetime.timedelta(seconds=60))
        second = service.issue_token(_make_request())
        assert second.token == first.token
        assert second.expires_at == first.expires_at

    def test_denials_are_not_cached(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        fake_sg.disabled_login = _LOGIN
        service = _make_service(fake_sg)
        with pytest.raises(_ForbiddenError):
            service.issue_token(_make_request())
        fake_sg.disabled_login = ''
        assert service.issue_token(_make_request()).login == _LOGIN

    def test_expires_at_is_sg_lifetime_minus_margin(
        self, fake_sg: FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base)
        issued = _make_service(fake_sg).issue_token(_make_request())
        assert issued.expires_at == base + datetime.timedelta(seconds=600 - 30)

    def test_issues_user_bound_token(
        self, fake_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        service = _make_service(fake_sg)
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER):
            issued = service.issue_token(_make_request())
        assert issued.token == f'rest-sudo_as_login:{_LOGIN}'
        assert issued.token_type == _REST_TYPE
        assert issued.login == _LOGIN
        assert issued.site_url == fake_sg.url
        assert fake_sg.rest_scopes == [f'sudo_as_login:{_LOGIN}']
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'issue'
        assert record['email'] == _EMAIL
        assert record['login'] == _LOGIN
        assert record['aud'] == _AUDIENCE
        # First 16 hex digits of SHA-256 for rest-sudo_as_login:jane.exec.
        expected_fingerprint = '69d14779f75c4310'
        assert record['token_fp'] == expected_fingerprint
        assert issued.token not in caplog.text

    def test_logins_do_not_share_cache(self, fake_sg: FakeSG) -> None:
        other_email = 'sam.ops@studio.example'
        other_login = 'sam.ops'
        fake_sg.known_emails[_EMAIL] = _LOGIN
        fake_sg.known_emails[other_email] = other_login
        service = _make_service(fake_sg)
        first = service.issue_token(_make_request())
        second = service.issue_token(_make_request(other_email))
        assert first.token == f'rest-sudo_as_login:{_LOGIN}'
        assert second.token == f'rest-sudo_as_login:{other_login}'
        assert fake_sg.rest_scopes == [f'sudo_as_login:{_LOGIN}', f'sudo_as_login:{other_login}']

    def test_lookup_outage_audits_upstream_unavailable(
        self, fake_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        fake_sg.fail_user_lookup = True
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER), pytest.raises(UserTokenError):
            _make_service(fake_sg).issue_token(_make_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['reason'] == 'upstream_unavailable'

    def test_short_sg_lifetime_is_invalid_response(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        fake_sg.rest_expires_in = 120
        with pytest.raises(UserTokenError) as caught:
            _make_service(fake_sg).issue_token(_make_request())
        assert (caught.value.status, caught.value.error) == (502, 'sg_invalid_response')

    @pytest.mark.parametrize(
        ('status', 'title', 'reject_key'),
        [
            (503, 'Authentication failed', False),
            (401, 'Authentication failed', True),
            (400, "The script does not have permission to 'sudo': usersvc", False),
            (401, 'Authentication failed', False),
            (400, 'sudo subsystem unavailable', False),
        ],
        ids=['server-error', 'service-key', 'minter-permission', 'auth-failure', 'sudo-adjacent'],
    )
    def test_sudo_mint_failure_classification(
        self, fake_sg: FakeSG, status: int, title: str, reject_key: bool
    ) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        service = _make_service(fake_sg)
        assert service._directory.resolve_login(_EMAIL) == _LOGIN
        if reject_key:
            fake_sg.rest_credentials = {'usersvc': 'not-the-configured-key'}
        else:
            fake_sg.fail_rest = True
            fake_sg.rest_failure_status = status
            fake_sg.rest_failure_title = title

        with pytest.raises(UserTokenError) as caught:
            service.issue_token(_make_request())

        expected = (503, 'upstream_unavailable') if status == 503 else (502, 'sg_rejected')
        assert (caught.value.status, caught.value.error) == expected
        request = fake_sg.requests[-1]
        assert request['path'] == '/api/v1.1/auth/access_token'
        assert parse_qs(str(request['body']))['scope'] == [f'sudo_as_login:{_LOGIN}']

    def test_token_is_cached_per_login(
        self, fake_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        service = _make_service(fake_sg)
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER):
            first = service.issue_token(_make_request())
            miss = json.loads(caplog.records[-1].getMessage())
            second = service.issue_token(_make_request())
        hit = json.loads(caplog.records[-1].getMessage())
        assert first.token == second.token
        assert fake_sg.rest_scopes == [f'sudo_as_login:{_LOGIN}']
        assert miss['cache'] == 'miss'
        assert hit['cache'] == 'hit'

    def test_unknown_email_is_forbidden(
        self, fake_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER), pytest.raises(_ForbiddenError):
            _make_service(fake_sg).issue_token(_make_request())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'deny'
        assert record['email'] == _EMAIL
        assert record['reason'] == 'forbidden'

    def test_unknown_type_audit_is_bounded_after_claims(
        self, offline_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        huge = 'B' * 48000
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER), pytest.raises(_BadRequestError):
            _make_service(offline_sg).issue_token(_make_request(token_type=huge))
        message = caplog.records[-1].getMessage()
        record = json.loads(message)
        assert record['token_type'] == _AUDIT_INVALID
        assert huge not in message
        assert len(message) < 512

    def test_wrong_domain_is_unauthorized(self, offline_sg: FakeSG) -> None:
        with pytest.raises(_UnauthorizedError):
            _make_service(offline_sg).issue_token(_make_request('intruder@evil.example'))


def _email_verifier(presented: str) -> Mapping[str, object]:
    if '@' not in presented:
        raise ValueError('forged token')
    return {'aud': _AUDIENCE, 'email': presented, 'email_verified': True, 'hd': _DOMAIN}


def _enable_session_user(fake_sg: FakeSG) -> None:
    fake_sg.known_emails[_EMAIL] = _LOGIN
    fake_sg.human_logins[_LOGIN] = 7
    fake_sg.rpc_unique_human_sessions = True


def _make_request(
    email: str = _EMAIL, token_type: str = _REST_TYPE, refresh: bool = False
) -> UserTokenRequest:
    return UserTokenRequest(
        authorization=f'Bearer {email}',
        source_ip='198.51.100.7',
        request_id='req1',
        token_type=token_type,
        refresh=refresh,
    )


def _make_service(
    fake_sg: FakeSG,
    verifier: Verifier = _email_verifier,
    token_types: frozenset[str] = frozenset({'rest'}),
    *,
    session_ttl_seconds: int = 600,
) -> UserTokenService:
    fake_sg.rest_credentials = {'usersvc': 'svc-credential'}
    minter = SGMinter(fake_sg.url, timeout=STALL_TIMEOUT_SECONDS)
    service = UserTokenService(
        ServiceAccount(fake_sg.url, 'usersvc', 'svc-credential'),
        ClaimsValidator(verifier, [_AUDIENCE], _DOMAIN),
        UserDirectory(fake_sg.url, minter, 'usersvc', 'svc-credential'),
        minter,
        AuditLogger(logging.getLogger(_AUDIT_LOGGER)),
        token_types=token_types,
        session_ttl_seconds=session_ttl_seconds,
    )
    service._cache._clock = lambda: 0.0
    return service


class TestSessionIssuance:
    def test_audit_records_token_type(
        self, fake_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=_SESSION_TYPES)
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER):
            service.issue_token(_make_request(token_type=_SESSION_TYPE))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['token_type'] == _SESSION_TYPE

    @pytest.mark.parametrize('kind', [_REST_TYPE, _SESSION_TYPE])
    def test_audit_records_valid_token_type_on_unauthorized(
        self, offline_sg: FakeSG, caplog: pytest.LogCaptureFixture, kind: str
    ) -> None:
        with (
            caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER),
            pytest.raises(_UnauthorizedError),
        ):
            _make_service(offline_sg).issue_token(_make_request('forged', token_type=kind))
        record = json.loads(caplog.records[-1].getMessage())
        assert record['token_type'] == kind

    def test_disallowed_type_is_forbidden_before_minting(self, offline_sg: FakeSG) -> None:
        _enable_session_user(offline_sg)
        service = _make_service(offline_sg, token_types=frozenset({'rest'}))
        with pytest.raises(_ForbiddenError):
            service.issue_token(_make_request(token_type=_SESSION_TYPE))

    def test_force_refresh_keeps_live_session(self, fake_sg: FakeSG) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=_SESSION_TYPES)
        first = service.issue_token(_make_request(token_type=_SESSION_TYPE))
        second = service.issue_token(_make_request(token_type=_SESSION_TYPE, refresh=True))
        assert second.token == first.token
        assert _sudo_mint_count(fake_sg) == 1

    def test_force_refresh_replaces_dead_session(self, fake_sg: FakeSG) -> None:
        _enable_session_user(fake_sg)
        service = _make_service(fake_sg, token_types=_SESSION_TYPES)
        first = service.issue_token(_make_request(token_type=_SESSION_TYPE))
        fake_sg.disabled_human_sessions.add(first.token)
        second = service.issue_token(_make_request(token_type=_SESSION_TYPE, refresh=True))
        assert second.token != first.token
        assert _sudo_mint_count(fake_sg) == 2

    def test_minter_fault_is_sg_rejected(self, fake_sg: FakeSG) -> None:
        _enable_session_user(fake_sg)
        fake_sg.rpc_sudo_mint_failures[('usersvc', _LOGIN)] = {
            'exception': True,
            'message': "The script does not have permission to 'sudo': usersvc",
            'error_code': 102,
        }
        with pytest.raises(UserTokenError) as caught:
            _make_service(fake_sg, token_types=_SESSION_TYPES).issue_token(
                _make_request(token_type=_SESSION_TYPE)
            )

        assert (caught.value.status, caught.value.error) == (502, 'sg_rejected')

    def test_rest_cache_until_equals_expires_at(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        issued = _make_service(fake_sg).issue_token(_make_request())
        assert issued.cache_until == issued.expires_at

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
        fake_sg: FakeSG,
        monkeypatch: pytest.MonkeyPatch,
        fault: str,
        display: str,
        status: int,
    ) -> None:
        _enable_session_user(fake_sg)
        fake_sg.rpc_sudo_mint_failures[('usersvc', _LOGIN)] = {
            'exception': True,
            'message': fault,
            'error_code': 102,
        }

        def formatted_message(_self: SGError) -> str:
            return display

        monkeypatch.setattr(SGError, '__str__', formatted_message)
        with pytest.raises(UserTokenError) as excinfo:
            _make_service(fake_sg, token_types=_SESSION_TYPES).issue_token(
                _make_request(token_type=_SESSION_TYPE)
            )
        assert excinfo.value.status == status

    def test_session_cache_is_per_login_and_type(
        self, fake_sg: FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_session_user(fake_sg)
        other_email = 'sam.ops@studio.example'
        other_login = 'sam.ops'
        fake_sg.known_emails[other_email] = other_login
        fake_sg.human_logins[other_login] = 8
        service = _make_service(fake_sg, token_types=frozenset({'rest', 'session'}))
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base)
        first = service.issue_token(_make_request(token_type=_SESSION_TYPE))
        monkeypatch.setattr(_usertoken, '_utcnow', lambda: base + datetime.timedelta(seconds=60))
        second = service.issue_token(_make_request(token_type=_SESSION_TYPE))
        assert second.token == first.token
        assert second.cache_until == first.cache_until
        other = service.issue_token(_make_request(other_email, token_type=_SESSION_TYPE))
        assert other.token != first.token
        assert fake_sg.web_sessions[first.token] == _LOGIN
        assert fake_sg.web_sessions[other.token] == other_login
        for email, issued in ((_EMAIL, first), (other_email, other)):
            for refresh in (False, True):
                reused = service.issue_token(
                    _make_request(email, token_type=_SESSION_TYPE, refresh=refresh)
                )
                assert reused.token == issued.token
                assert reused.cache_until == issued.cache_until
        assert _sudo_mint_count(fake_sg) == 2
        rest = service.issue_token(_make_request())
        assert rest.token != first.token

    def test_session_type_mints_sudo_session(
        self, fake_sg: FakeSG, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_session_user(fake_sg)
        base = datetime.datetime(2026, 6, 12, 12, 0, tzinfo=datetime.UTC)
        elapsed = 0
        monkeypatch.setattr(
            _usertoken, '_utcnow', lambda: base + datetime.timedelta(seconds=elapsed)
        )
        service = _make_service(fake_sg, token_types=_SESSION_TYPES, session_ttl_seconds=173)
        service._cache._clock = lambda: elapsed
        request = _make_request(token_type=_SESSION_TYPE)
        issued = service.issue_token(request)
        assert issued.token_type == _SESSION_TYPE
        assert issued.token.startswith('sess-sudo-mint-')
        assert issued.login == _LOGIN
        assert issued.expires_at is None
        assert issued.cache_until == base + datetime.timedelta(seconds=173)
        elapsed = 172
        assert service.issue_token(request) == issued
        assert _sudo_mint_count(fake_sg) == 1
        elapsed = 173
        renewed = service.issue_token(request)
        assert renewed.cache_until == base + datetime.timedelta(seconds=346)
        assert _sudo_mint_count(fake_sg) == 2

    def test_target_refusal_is_forbidden(
        self, fake_sg: FakeSG, caplog: pytest.LogCaptureFixture
    ) -> None:
        _enable_session_user(fake_sg)
        fake_sg.rpc_sudo_mint_failures[('usersvc', _LOGIN)] = {
            'exception': True,
            'message': "Cannot 'sudo' - inactive user account: 'jane.exec' (svc-credential)",
            'error_code': 102,
        }
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER), pytest.raises(_ForbiddenError):
            _make_service(fake_sg, token_types=_SESSION_TYPES).issue_token(
                _make_request(token_type=_SESSION_TYPE)
            )
        detail = json.loads(caplog.records[-1].getMessage())['detail']
        assert 'RPC 102' in detail
        assert 'session token request' in detail
        assert 'svc-credential' not in caplog.text

    @pytest.mark.parametrize(
        ('kind', 'expected'),
        [
            (_REST_TYPE, _REST_TYPE),
            (_SESSION_TYPE, _SESSION_TYPE),
            (_BOGUS_TYPE, _AUDIT_INVALID),
        ],
    )
    def test_unhandled_audit_classifies_token_type(
        self,
        offline_sg: FakeSG,
        caplog: pytest.LogCaptureFixture,
        kind: str,
        expected: str,
    ) -> None:
        service = _make_service(offline_sg)
        with caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER):
            service.log_unhandled(_make_request(token_type=kind), RuntimeError())
        record = json.loads(caplog.records[-1].getMessage())
        assert record['event'] == 'error'
        assert record['token_type'] == expected


def _sudo_mint_count(fake_sg: FakeSG) -> int:
    return sum(
        1
        for entry in fake_sg.requests
        if entry['path'] == '/api3/json'
        and 'sudo_as_login' in str(entry['body'])
        and 'script_name' in str(entry['body'])
    )


def test_directory_transport_failure_protects_bearer(
    offline_sg: FakeSG, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    bearer = 'synthetic-directory-credential'
    service = _make_service(offline_sg)
    monkeypatch.setattr(service._directory, '_lookup_bearer', Mock(return_value=bearer))
    get = Mock(side_effect=OSError(f'lookup failed using {bearer}'))
    monkeypatch.setattr(service._directory._session, 'get', get)
    with (
        caplog.at_level(logging.INFO, logger=_AUDIT_LOGGER),
        pytest.raises(UserTokenError) as caught,
    ):
        service.issue_token(_make_request())
    record = json.loads(caplog.records[-1].getMessage())
    assert record['reason'] == 'upstream_unavailable'
    assert record['detail'] == 'SG user lookup could not be sent: OSError'
    assert bearer not in caplog.text
    assert bearer not in ''.join(traceback.format_exception(caught.value))


def test_service_account_repr_omits_script_key() -> None:
    account = ServiceAccount('https://studio.example', 'service-script', 'secret-key-value')
    assert 'secret-key-value' not in repr(account)


def test_target_denial_uses_local_diagnosis() -> None:
    title = 'Cannot sudo as inactive user'
    response = Mock(status_code=401, json=Mock(return_value={'errors': [{'title': title}]}))
    minter = SGMinter('https://sg.example', session=Mock(post=Mock(return_value=response)))
    with pytest.raises(SGError) as caught:
        minter.mint_rest_token('script', 'sudo', scope='sudo_as_login:inactive')
    assert 'sudo' not in str(caught.value)
    assert isinstance(_usertoken._map_mint_error(caught.value), _ForbiddenError)
