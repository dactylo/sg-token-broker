from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from sg_token_broker._sg import SGMinter
from sg_token_broker._users import UnknownUserError, UserDirectory, UserLookupError
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

    def test_lookup_token_is_reused_across_misses(self, fake_sg: FakeSG) -> None:
        fake_sg.known_emails.update({_EMAIL: _LOGIN, _OTHER_EMAIL: _OTHER_LOGIN})
        directory = _make_directory(fake_sg)

        assert directory.resolve_login(_EMAIL) == _LOGIN
        assert directory.resolve_login(_OTHER_EMAIL) == _OTHER_LOGIN

        assert len(_mint_requests(fake_sg)) == 1

    def test_mint_failure_raises_lookup_error(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        with pytest.raises(UserLookupError):
            _make_directory(fake_sg).resolve_login(_EMAIL)

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

        with pytest.raises(UserLookupError, match='HTTP 401'):
            _make_directory(fake_sg).resolve_login(_EMAIL)

        assert len(_mint_requests(fake_sg)) == 2

    def test_remote_http_is_rejected(self) -> None:
        with pytest.raises(UserLookupError, match='https'):
            UserDirectory(
                'http://sg.studio.internal',
                SGMinter('https://sg.studio.internal'),
                'usersvc',
                'svc-credential',
            )

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
        with pytest.raises(UserLookupError):
            directory.resolve_login(_EMAIL)
        fake_sg.fail_user_lookup = False
        fake_sg.known_emails[_EMAIL] = _LOGIN
        assert directory.resolve_login(_EMAIL) == _LOGIN


def _lookup_requests(fake_sg: FakeSG) -> list[dict[str, object]]:
    return [r for r in fake_sg.requests if str(r['path']).startswith('/api/v1.1/entity/human')]


def _make_directory(fake_sg: FakeSG) -> UserDirectory:
    return UserDirectory(fake_sg.url, SGMinter(fake_sg.url), 'usersvc', 'svc-credential')


def _mint_requests(fake_sg: FakeSG) -> list[dict[str, object]]:
    return [r for r in fake_sg.requests if r['path'] == '/api/v1.1/auth/access_token']


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    with pytest.raises(UserLookupError) as caught:
        UserDirectory('https://127.0.0.1:1', SGMinter('https://127.0.0.1:1'), 's', 'k')._query(
            _EMAIL, 'bearer'
        )
    assert isinstance(caught.value.__cause__, OSError)
    assert not isinstance(caught.value.__cause__, requests.RequestException)
    assert str(caught.value) == 'SG user lookup could not be sent: ' + str(caught.value.__cause__)
    assert str(missing) in str(caught.value)
