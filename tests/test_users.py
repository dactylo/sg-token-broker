from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from sg_token_broker import _users
from sg_token_broker._sg import SGMinter
from sg_token_broker._users import UnknownUserError, UserDirectory, UserLookupError
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.conftest import FakeSG

_EMAIL = 'jane.exec@studio.example'
_LOGIN = 'jane.exec'
_OTHER_EMAIL = 'sam.lead@studio.example'
_OTHER_LOGIN = 'sam.lead'


class TestResolveLogin:
    def test_ambiguous_email_raises_and_is_not_cached(self, fake_sg: FakeSG) -> None:
        fake_sg.duplicate_email = _EMAIL
        directory = _make_directory(fake_sg)
        with pytest.raises(UnknownUserError):
            directory.resolve_login(_EMAIL)
        fake_sg.duplicate_email = ''
        fake_sg.known_emails[_EMAIL] = _LOGIN
        assert directory.resolve_login(_EMAIL) == _LOGIN

    def test_apostrophe_in_local_part_resolves(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails["o'brien@studio.example"] = 'obrien'
        assert _make_directory(fake_sg).resolve_login("o'brien@studio.example") == 'obrien'

    def test_blank_login_is_rejected_without_caching(self, fake_sg: FakeSG) -> None:
        directory = _make_directory(fake_sg)
        fake_sg.known_emails[_EMAIL] = '  '
        with pytest.raises(UserLookupError) as caught:
            directory.resolve_login(_EMAIL)
        assert caught.value.kind == 'invalid_response'

        padded_login = f' {_LOGIN} '
        fake_sg.known_emails[_EMAIL] = padded_login
        assert directory.resolve_login(_EMAIL) == padded_login

    def test_email_is_case_insensitive(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        assert _make_directory(fake_sg).resolve_login('Jane.Exec@Studio.Example') == _LOGIN

    def test_filter_altering_email_is_rejected_without_query(self, offline_sg: FakeSG) -> None:
        directory = _make_directory(offline_sg)
        with pytest.raises(UnknownUserError):
            directory.resolve_login('ghost@nowhere.example,jane.exec@studio.example')

    def test_lookup_authenticates_with_a_plain_token(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        _make_directory(fake_sg).resolve_login(_EMAIL)
        assert fake_sg.rest_scopes == []
        assert _lookup_requests(fake_sg)[0]['bearer'] == fake_sg.canned_rest

    def test_lookup_timeout(self, offline_sg: FakeSG, monkeypatch: pytest.MonkeyPatch) -> None:
        directory = _make_directory(offline_sg)
        directory._bearer = ('cached', 300.0)
        monkeypatch.setattr(directory._session, 'get', Mock(side_effect=requests.Timeout()))
        with pytest.raises(UserLookupError) as caught:
            directory.resolve_login(_EMAIL)
        assert caught.value.kind == 'unavailable'

    def test_lookup_token_is_reused_across_misses(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails.update({_EMAIL: _LOGIN, _OTHER_EMAIL: _OTHER_LOGIN})
        directory = _make_directory(fake_sg)

        assert directory.resolve_login(_EMAIL) == _LOGIN
        assert directory.resolve_login(_OTHER_EMAIL) == _OTHER_LOGIN

        assert len(_mint_requests(fake_sg)) == 1

    def test_mint_failure_raises_lookup_error(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        with pytest.raises(UserLookupError) as caught:
            _make_directory(fake_sg).resolve_login(_EMAIL)
        assert caught.value.kind == 'rejected'

    def test_non_json_lookup(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_entities_status = 200
        fake_sg.entities_non_json = True
        with pytest.raises(UserLookupError) as caught:
            _make_directory(fake_sg).resolve_login(_EMAIL)
        assert caught.value.kind == 'invalid_response'

    def test_rejected_lookup_token_is_reminted_once(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails.update({_EMAIL: _LOGIN, _OTHER_EMAIL: _OTHER_LOGIN})
        directory = _make_directory(fake_sg)
        directory.resolve_login(_EMAIL)
        first, second = fake_sg.canned_rest, 'rest-token-2'
        fake_sg.dead_bearers.append(first)
        fake_sg.canned_rest = second

        assert directory.resolve_login(_OTHER_EMAIL) == _OTHER_LOGIN

        assert [r['bearer'] for r in _lookup_requests(fake_sg)] == [first, first, second]
        assert len(_mint_requests(fake_sg)) == 2

    def test_rejected_replacement_token_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        fake_sg.dead_bearers.append(fake_sg.canned_rest)

        with pytest.raises(UserLookupError, match='HTTP 401') as caught:
            _make_directory(fake_sg).resolve_login(_EMAIL)

        assert caught.value.kind == 'rejected'
        assert len(_mint_requests(fake_sg)) == 2

    def test_remote_http_is_rejected(self) -> None:
        with pytest.raises(UserLookupError, match='https') as caught:
            UserDirectory(
                'http://sg.studio.internal',
                SGMinter('https://sg.studio.internal'),
                'usersvc',
                'svc-credential',
            )

        assert caught.value.kind is None

    def test_resolves_and_caches(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails[_EMAIL] = _LOGIN
        directory = _make_directory(fake_sg)
        assert directory.resolve_login(_EMAIL) == _LOGIN
        assert directory.resolve_login(_EMAIL) == _LOGIN
        assert len(_lookup_requests(fake_sg)) == 1

    def test_short_lived_lookup_token_is_not_reused(self, fake_sg: FakeSG) -> None:
        # SG's reported lifetime, less the 30 s margin, leaves no reuse window.
        fake_sg.rest_expires_in = 30
        fake_sg.known_emails.update({_EMAIL: _LOGIN, _OTHER_EMAIL: _OTHER_LOGIN})
        directory = _make_directory(fake_sg)

        directory.resolve_login(_EMAIL)
        directory.resolve_login(_OTHER_EMAIL)

        assert len(_mint_requests(fake_sg)) == 2

    def test_unknown_email_is_not_cached(self, fake_sg: FakeSG) -> None:
        directory = _make_directory(fake_sg)
        with pytest.raises(UnknownUserError):
            directory.resolve_login(_EMAIL)
        fake_sg.known_emails[_EMAIL] = _LOGIN
        assert directory.resolve_login(_EMAIL) == _LOGIN

    def test_upstream_failure_raises_lookup_error(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_user_lookup = True
        directory = _make_directory(fake_sg)
        with pytest.raises(UserLookupError) as caught:
            directory.resolve_login(_EMAIL)
        assert caught.value.kind == 'unavailable'
        fake_sg.fail_user_lookup = False
        fake_sg.known_emails[_EMAIL] = _LOGIN
        assert directory.resolve_login(_EMAIL) == _LOGIN


def _lookup_requests(fake_sg: FakeSG) -> list[dict[str, object]]:
    return [r for r in fake_sg.requests if str(r['path']).startswith('/api/v1.1/entity/human')]


def _make_directory(fake_sg: FakeSG) -> UserDirectory:
    directory = UserDirectory(
        fake_sg.url,
        SGMinter(fake_sg.url, timeout=STALL_TIMEOUT_SECONDS),
        'usersvc',
        'svc-credential',
    )
    directory._cache._clock = lambda: 0.0
    return directory


def _mint_requests(fake_sg: FakeSG) -> list[dict[str, object]]:
    return [r for r in fake_sg.requests if r['path'] == '/api/v1.1/auth/access_token']


@pytest.fixture(autouse=True)
def lookup_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_users, 'time', SimpleNamespace(monotonic=lambda: 0.0))


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    with pytest.raises(UserLookupError) as caught:
        UserDirectory(
            'https://127.0.0.1:1',
            SGMinter('https://127.0.0.1:1', timeout=STALL_TIMEOUT_SECONDS),
            's',
            'k',
        )._query(_EMAIL, 'bearer')
    assert caught.value.__suppress_context__
    assert str(caught.value).startswith(
        'SG user lookup could not be sent: Could not find a suitable TLS CA certificate bundle'
    )
    assert str(missing) in str(caught.value)
