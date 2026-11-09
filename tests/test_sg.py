import json
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from sg_token_broker._sg import MintedToken, SGError, SGMinter
from tests.conftest import FakeSG


class TestCheckSessionToken:
    @pytest.mark.parametrize(
        ('nested_results', 'session_id'),
        [(False, ''), (False, '  \t'), (True, ''), (True, '  \t')],
    )
    def test_blank_session_id_raises(
        self,
        fake_sg: FakeSG,
        nested_results: bool,
        session_id: str,
    ) -> None:
        fake_sg.nested_results = nested_results
        fake_sg.rpc_session_id_override = session_id
        with pytest.raises(SGError, match='session_id'):
            SGMinter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_connection_error_raises(self) -> None:
        with pytest.raises(SGError):
            SGMinter('http://127.0.0.1:1', timeout=0.2).check_session_token('t')

    def test_float_auth_code_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_fault = True
        fake_sg.rpc_error_code_override = 102.0
        with pytest.raises(SGError, match='probe failed'):
            SGMinter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_live_token_is_valid(self, fake_sg: FakeSG) -> None:
        minter = SGMinter(fake_sg.url)
        minted = minter.mint_session_token('s', 'k')
        assert minter.check_session_token(minted.token) is True

    def test_malformed_probe_response_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_missing_session_id = True
        with pytest.raises(SGError, match='session_id'):
            SGMinter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_non_auth_fault_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_fault = True
        with pytest.raises(SGError, match='probe failed'):
            SGMinter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_revoked_token_is_invalid(self, fake_sg: FakeSG) -> None:
        minter = SGMinter(fake_sg.url)
        minted = minter.mint_session_token('s', 'k')
        fake_sg.session_revoked = True
        assert minter.check_session_token(minted.token) is False

    def test_unknown_token_is_invalid(self, fake_sg: FakeSG) -> None:
        assert SGMinter(fake_sg.url).check_session_token('bogus') is False


class TestMintRestToken:
    def test_boolean_expiry_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rest_expires_in = True
        with pytest.raises(SGError, match='expires_in'):
            SGMinter(fake_sg.url).mint_rest_token('s', 'k')

    def test_mints_and_strips_refresh_token(self, fake_sg: FakeSG) -> None:
        minted = SGMinter(fake_sg.url).mint_rest_token('scriptname', 'scriptkey')
        assert minted.token == fake_sg.canned_rest
        assert minted.expires_in == 600
        assert 'refresh' not in minted.token

    def test_rest_failure_preserves_error_title(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        fake_sg.rest_failure_status = 401
        fake_sg.rest_failure_title = 'Cannot sudo as that user'
        minter = SGMinter(fake_sg.url)
        with pytest.raises(SGError) as excinfo:
            minter.mint_rest_token('script', 'key', scope='sudo_as_login:a')
        assert excinfo.value.status_code == 401
        assert excinfo.value.error_title == 'Cannot sudo as that user'


class TestMintRestTokenScope:
    def test_connection_error_has_no_status_code(self) -> None:
        with pytest.raises(SGError) as excinfo:
            SGMinter('http://127.0.0.1:1', timeout=0.2).mint_rest_token('s', 'k')
        assert excinfo.value.status_code is None

    def test_error_carries_upstream_detail(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        with pytest.raises(SGError) as excinfo:
            SGMinter(fake_sg.url).mint_rest_token('s', 'k')
        message = str(excinfo.value)
        assert 'HTTP 401' in message
        assert 'Authentication failed' in message

    def test_no_scope_omits_the_field(self, fake_sg: FakeSG) -> None:
        SGMinter(fake_sg.url).mint_rest_token('s', 'k')
        assert fake_sg.rest_scopes == []

    def test_sudo_scope_is_sent_and_binds_the_token(self, fake_sg: FakeSG) -> None:
        scope = 'sudo_as_login:jane'
        minted = SGMinter(fake_sg.url).mint_rest_token('s', 'k', scope=scope)
        assert fake_sg.rest_scopes == [scope]
        assert minted.token == f'rest-{scope}'


class TestMintSessionToken:
    def test_connection_error_raises(self) -> None:
        minter = SGMinter('http://127.0.0.1:1', timeout=0.2)
        with pytest.raises(SGError):
            minter.mint_session_token('s', 'k')

    def test_mint_session_token_sends_sudo_login(self, fake_sg: FakeSG) -> None:
        fake_sg.human_logins['jane.doe'] = 7
        minter = SGMinter(fake_sg.url)
        minter.mint_session_token('script', 'key', sudo_login='jane.doe')
        assert _last_rpc_params(fake_sg)['sudo_as_login'] == 'jane.doe'

    def test_mints(self, fake_sg: FakeSG) -> None:
        minter = SGMinter(fake_sg.url)
        minted = minter.mint_session_token('scriptname', 'scriptkey')
        assert minted.token == fake_sg.canned_session
        assert minted.expires_in is None
        body = json.loads(str(fake_sg.requests[0]['body']))
        assert body['method_name'] == 'get_session_token'
        assert body['params'] == [{'script_name': 'scriptname', 'script_key': 'scriptkey'}]

    def test_preserves_nonempty_session_id(self, fake_sg: FakeSG) -> None:
        expected = '  padded-token  '
        fake_sg.rpc_session_id_override = expected
        minted = SGMinter(fake_sg.url).mint_session_token('s', 'k')
        assert minted.token == expected

    def test_rpc_exception_raises_sanitized(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rpc = True
        with pytest.raises(SGError, match='Cannot authenticate'):
            SGMinter(fake_sg.url).mint_session_token('s', 'k')

    def test_rpc_failure_caps_long_message(self, fake_sg: FakeSG) -> None:
        prefix = 'SG rejected session token request: '
        fake_sg.rpc_sudo_mint_failures[('script', 'a')] = {
            'exception': True,
            'message': 'x' * 500,
            'error_code': 102,
        }
        minter = SGMinter(fake_sg.url)
        with pytest.raises(SGError) as excinfo:
            minter.mint_session_token('script', 'key', sudo_login='a')
        assert len(str(excinfo.value)) <= len(prefix) + 120
        assert excinfo.value.error_code == 102
        assert excinfo.value.rpc_message == 'x' * 120

    def test_rpc_failure_preserves_error_code_and_message(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_sudo_mint_failures[('script', 'a')] = {
            'exception': True,
            'message': "Cannot 'sudo' - inactive user account: 'a'",
            'error_code': 102,
        }
        minter = SGMinter(fake_sg.url)
        with pytest.raises(SGError) as excinfo:
            minter.mint_session_token('script', 'key', sudo_login='a')
        assert excinfo.value.error_code == 102
        assert 'inactive user account' in str(excinfo.value)
        assert excinfo.value.rpc_message == "Cannot 'sudo' - inactive user account: 'a'"

    def test_rpc_failure_replaces_non_string_message(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_sudo_mint_failures[('script', 'a')] = {
            'exception': True,
            'message': ['not', 'a', 'string'],
            'error_code': 102,
        }
        minter = SGMinter(fake_sg.url)
        with pytest.raises(SGError) as excinfo:
            minter.mint_session_token('script', 'key', sudo_login='a')
        assert str(excinfo.value) == 'SG rejected session token request: unknown error'
        assert excinfo.value.error_code == 102


class TestMintedTokenRepr:
    def test_repr_hides_the_token(self) -> None:
        value = 'secret-token-value'
        minted = MintedToken(token=value, expires_in=600)
        assert value not in repr(minted)
        assert value not in str(minted)


class TestNestedResultsFallback:
    def test_mints_from_legacy_nested_shape(self, fake_sg: FakeSG) -> None:
        fake_sg.nested_results = True
        minted = SGMinter(fake_sg.url).mint_session_token('s', 'k')
        assert minted.token == fake_sg.canned_session


class TestSGMinter:
    def test_credential_post_disables_redirects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        response = requests.Response()
        response.status_code = 307
        response.raw = BytesIO(b'{}')
        session = requests.Session()
        post = Mock(return_value=response)
        monkeypatch.setattr(session, 'post', post)

        with pytest.raises(SGError, match='HTTP 307'):
            SGMinter('https://studio.example.com', session=session).mint_rest_token('s', 'k')

        assert post.call_args.kwargs['allow_redirects'] is False

    def test_loopback_http_is_accepted_without_request(self, offline_sg: FakeSG) -> None:
        SGMinter(offline_sg.url)

    def test_remote_http_is_rejected(self) -> None:
        with pytest.raises(SGError, match='https'):
            SGMinter('http://sg.studio.internal')


def _last_rpc_params(fake_sg: FakeSG) -> dict[str, object]:
    body = json.loads(str(fake_sg.requests[-1]['body']))
    return body['params'][0]


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    monkeypatch.setattr(
        'urllib3.connection.HTTPSConnection.connect',
        Mock(side_effect=AssertionError('unexpected connection')),
    )
    with pytest.raises(SGError) as caught:
        SGMinter('https://127.0.0.1:1').mint_session_token('s', 'k')
    assert isinstance(caught.value.__cause__, OSError)
    assert not isinstance(caught.value.__cause__, requests.RequestException)
    assert str(caught.value) == 'SG request to /api3/json could not be sent: ' + str(
        caught.value.__cause__
    )
    assert str(missing) in str(caught.value)
