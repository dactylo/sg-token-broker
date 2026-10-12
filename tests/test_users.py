import pytest

from sg_token_broker._sg import SGMinter
from sg_token_broker._users import UnknownUserError, UserDirectory, UserLookupError
from tests.conftest import _FakeSG

EMAIL = 'jane.exec@studio.example'
LOGIN = 'jane.exec'


class TestResolveLogin:
    def test_ambiguous_email_raises_and_is_not_cached(self, fake_sg: _FakeSG) -> None:
        fake_sg._duplicate_email = EMAIL
        directory = _make_directory(fake_sg)
        with pytest.raises(UnknownUserError):
            directory.resolve_login(EMAIL)
        fake_sg._duplicate_email = ''
        fake_sg._known_emails[EMAIL] = LOGIN
        assert directory.resolve_login(EMAIL) == LOGIN

    def test_apostrophe_in_local_part_resolves(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails["o'brien@studio.example"] = 'obrien'
        assert _make_directory(fake_sg).resolve_login("o'brien@studio.example") == 'obrien'

    def test_email_is_case_insensitive(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        assert _make_directory(fake_sg).resolve_login('Jane.Exec@Studio.Example') == LOGIN

    def test_filter_altering_email_is_rejected_without_query(self, fake_sg: _FakeSG) -> None:
        directory = _make_directory(fake_sg)
        with pytest.raises(UnknownUserError):
            directory.resolve_login('ghost@nowhere.example,jane.exec@studio.example')
        assert _lookup_requests(fake_sg) == []

    def test_lookup_authenticates_with_a_plain_token(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        _make_directory(fake_sg).resolve_login(EMAIL)
        assert fake_sg._rest_scopes == []
        assert _lookup_requests(fake_sg)[0]['bearer'] == fake_sg._canned_rest

    def test_mint_failure_raises_lookup_error(self, fake_sg: _FakeSG) -> None:
        fake_sg._fail_rest = True
        with pytest.raises(UserLookupError):
            _make_directory(fake_sg).resolve_login(EMAIL)

    def test_remote_http_is_rejected(self) -> None:
        with pytest.raises(UserLookupError, match='https'):
            UserDirectory(
                'http://sg.studio.internal',
                SGMinter('https://sg.studio.internal'),
                'usersvc',
                'svc-credential',
            )

    def test_resolves_and_caches(self, fake_sg: _FakeSG) -> None:
        fake_sg._known_emails[EMAIL] = LOGIN
        directory = _make_directory(fake_sg)
        assert directory.resolve_login(EMAIL) == LOGIN
        assert directory.resolve_login(EMAIL) == LOGIN
        assert len(_lookup_requests(fake_sg)) == 1

    def test_unknown_email_is_not_cached(self, fake_sg: _FakeSG) -> None:
        directory = _make_directory(fake_sg)
        with pytest.raises(UnknownUserError):
            directory.resolve_login(EMAIL)
        fake_sg._known_emails[EMAIL] = LOGIN
        assert directory.resolve_login(EMAIL) == LOGIN

    def test_upstream_failure_raises_lookup_error(self, fake_sg: _FakeSG) -> None:
        fake_sg._fail_user_lookup = True
        directory = _make_directory(fake_sg)
        with pytest.raises(UserLookupError):
            directory.resolve_login(EMAIL)
        fake_sg._fail_user_lookup = False
        fake_sg._known_emails[EMAIL] = LOGIN
        assert directory.resolve_login(EMAIL) == LOGIN


def _lookup_requests(fake_sg: _FakeSG) -> list[dict[str, object]]:
    return [r for r in fake_sg._requests if str(r['path']).startswith('/api/v1.1/entity/human')]


def _make_directory(fake_sg: _FakeSG) -> UserDirectory:
    return UserDirectory(fake_sg._url, SGMinter(fake_sg._url), 'usersvc', 'svc-credential')
