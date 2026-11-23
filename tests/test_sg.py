import json
import traceback
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs

import pytest
import requests

from sg_token_broker import _sg
from sg_token_broker._sg import MintedToken, SGError, SGMinter
from tests._timeouts import STALL_TIMEOUT_SECONDS
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
            _minter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_float_auth_code_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_fault = True
        fake_sg.rpc_error_code_override = 102.0
        with pytest.raises(SGError, match='probe failed'):
            _minter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_live_token_is_valid(self, fake_sg: FakeSG) -> None:
        minter = _minter(fake_sg.url)
        minted = minter.mint_session_token('s', 'k')
        assert minter.check_session_token(minted.token) is True
        probe = json.loads(str(fake_sg.requests[-1]['body']))
        assert probe['method_name'] == 'get_session_token'
        assert probe['params'] == [{'session_token': minted.token, 'reject_if_expired': True}]
        assert probe['params'][0]['reject_if_expired'] is True

    def test_malformed_probe_response_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_missing_session_id = True
        with pytest.raises(SGError, match='session_id'):
            _minter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_non_auth_fault_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rpc_fault = True
        with pytest.raises(SGError, match='probe failed'):
            _minter(fake_sg.url).check_session_token(fake_sg.canned_session)

    def test_revoked_token_is_invalid(self, fake_sg: FakeSG) -> None:
        minter = _minter(fake_sg.url)
        minted = minter.mint_session_token('s', 'k')
        fake_sg.session_revoked = True
        assert minter.check_session_token(minted.token) is False

    def test_unknown_token_is_invalid(self, fake_sg: FakeSG) -> None:
        assert _minter(fake_sg.url).check_session_token('bogus') is False


class TestMintRestToken:
    def test_boolean_expiry_raises(self, fake_sg: FakeSG) -> None:
        fake_sg.rest_expires_in = True
        with pytest.raises(SGError, match='expires_in'):
            _minter(fake_sg.url).mint_rest_token('s', 'k')

    def test_mints_rest_token_with_client_credentials(self, fake_sg: FakeSG) -> None:
        minted = _minter(fake_sg.url).mint_rest_token('scriptname', 'scriptkey')
        assert minted.token == fake_sg.canned_rest
        assert minted.expires_in == 600
        assert parse_qs(str(fake_sg.requests[-1]['body']), keep_blank_values=True) == {
            'grant_type': ['client_credentials'],
            'client_id': ['scriptname'],
            'client_secret': ['scriptkey'],
        }

    def test_rest_failure_identifies_refused_target(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        fake_sg.rest_failure_status = 401
        fake_sg.rest_failure_title = 'Cannot sudo as that user'
        minter = _minter(fake_sg.url)
        with pytest.raises(SGError) as excinfo:
            minter.mint_rest_token('script', 'key', scope='sudo_as_login:a')
        assert excinfo.value.status_code == 401
        assert excinfo.value.target_refused
        assert 'check the target SG user' in str(excinfo.value)


class TestMintRestTokenScope:
    def test_error_identifies_script_credentials(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rest = True
        with pytest.raises(SGError) as excinfo:
            _minter(fake_sg.url).mint_rest_token('s', 'k')
        message = str(excinfo.value)
        assert 'HTTP 401' in message
        assert 'check the SG script name and key' in message

    def test_sudo_scope_is_sent_and_binds_the_token(self, fake_sg: FakeSG) -> None:
        scope = 'sudo_as_login:jane'
        minted = _minter(fake_sg.url).mint_rest_token('s', 'k', scope=scope)
        assert fake_sg.rest_scopes == [scope]
        assert minted.token == f'rest-{scope}'


class TestMintSessionToken:
    def test_mint_session_token_sends_sudo_login(self, fake_sg: FakeSG) -> None:
        fake_sg.human_logins['jane.doe'] = 7
        minter = _minter(fake_sg.url)
        minter.mint_session_token('script', 'key', sudo_login='jane.doe')
        assert _last_rpc_params(fake_sg)['sudo_as_login'] == 'jane.doe'

    def test_mints(self, fake_sg: FakeSG) -> None:
        minter = _minter(fake_sg.url)
        minted = minter.mint_session_token('scriptname', 'scriptkey')
        assert minted.token == fake_sg.canned_session
        assert minted.expires_in is None
        body = json.loads(str(fake_sg.requests[0]['body']))
        assert body['method_name'] == 'get_session_token'
        assert body['params'] == [{'script_name': 'scriptname', 'script_key': 'scriptkey'}]

    def test_preserves_nonempty_session_id(self, fake_sg: FakeSG) -> None:
        expected = '  padded-token  '
        fake_sg.rpc_session_id_override = expected
        minted = _minter(fake_sg.url).mint_session_token('s', 'k')
        assert minted.token == expected

    def test_rpc_exception_raises_sanitized(self, fake_sg: FakeSG) -> None:
        fake_sg.fail_rpc = True
        with pytest.raises(SGError, match='check the SG script name and key'):
            _minter(fake_sg.url).mint_session_token('s', 'k')


class TestMintedTokenRepr:
    def test_repr_hides_the_token(self) -> None:
        value = 'secret-token-value'
        minted = MintedToken(token=value, expires_in=600)
        assert value not in repr(minted)
        assert value not in str(minted)


class TestNestedResultsFallback:
    def test_mints_from_legacy_nested_shape(self, fake_sg: FakeSG) -> None:
        fake_sg.nested_results = True
        minted = _minter(fake_sg.url).mint_session_token('s', 'k')
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
            _minter('https://studio.example.com', session=session).mint_rest_token('s', 'k')

        assert post.call_args.kwargs['allow_redirects'] is False

    def test_loopback_http_is_accepted_without_request(self, offline_sg: FakeSG) -> None:
        SGMinter(offline_sg.url)

    def test_remote_http_is_rejected(self) -> None:
        with pytest.raises(SGError, match='https'):
            SGMinter('http://sg.studio.internal')


def _last_rpc_params(fake_sg: FakeSG) -> dict[str, object]:
    body = json.loads(str(fake_sg.requests[-1]['body']))
    return body['params'][0]


def _minter(site_url: str, *, session: requests.Session | None = None) -> SGMinter:
    return SGMinter(site_url, timeout=STALL_TIMEOUT_SECONDS, session=session)


@pytest.mark.parametrize(
    ('kind', 'status', 'body', 'failure', 'expected'),
    [
        (
            'session',
            200,
            {'exception': True, 'error_code': 102, 'message': 'refused'},
            None,
            'rejected',
        ),
        ('session', 200, {'exception': True, 'message': 'refused'}, None, 'rejected'),
        ('rest', 401, {}, None, 'rejected'),
        ('rest', 403, {}, None, 'rejected'),
        ('rest', 429, {}, None, 'unavailable'),
        ('rest', 503, {}, None, 'unavailable'),
        ('rest', 0, {}, requests.ConnectionError(), 'unavailable'),
        ('rest', 0, {}, requests.Timeout(), 'unavailable'),
        ('session', 200, {}, None, 'invalid_response'),
        ('rest', 204, {}, None, 'invalid_response'),
        ('session', 201, {'session_id': 'unexpected'}, None, 'invalid_response'),
        ('rest', 200, {'expires_in': 600}, None, 'invalid_response'),
        ('rest', 200, {'access_token': '  ', 'expires_in': 600}, None, 'invalid_response'),
    ],
)
def test_classify_sg_failure(
    kind: str, status: int, body: dict[str, object], failure: Exception | None, expected: str
) -> None:
    response = requests.Response()
    response.status_code = status
    response.raw = BytesIO(json.dumps(body).encode())
    session = Mock(spec=requests.Session)
    session.post = Mock(return_value=response, side_effect=failure)
    minter = _minter('https://studio.example', session=session)
    mint = minter.mint_session_token if kind == 'session' else minter.mint_rest_token
    with pytest.raises(SGError) as caught:
        mint('s', 'k')
    if failure is not None:
        assert caught.value.status_code is None
    if expected == 'invalid_response':
        assert isinstance(caught.value, _sg.SGInvalidResponseError)
    assert _sg.classify_sg_failure(caught.value) == expected


def test_missing_ca_bundle_is_a_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / 'missing-ca.pem'
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(missing))
    with pytest.raises(SGError) as caught:
        _minter('https://127.0.0.1:1').mint_session_token('s', 'synthetic-script-credential')
    assert caught.value.__suppress_context__
    assert str(caught.value).startswith(
        'SG request to /api3/json could not be sent: '
        'Could not find a suitable TLS CA certificate bundle'
    )
    assert str(missing) in str(caught.value)


@pytest.mark.parametrize('expires_in', [0, -1])
def test_non_positive_expires_in_is_invalid(fake_sg: FakeSG, expires_in: int) -> None:
    fake_sg.rest_expires_in = expires_in
    with pytest.raises(_sg.SGInvalidResponseError, match='expires_in'):
        _minter(fake_sg.url).mint_rest_token('s', 'k')


@pytest.mark.parametrize(
    ('code', 'diagnosis', 'hint'),
    [
        (102, "Cannot 'sudo' - inactive user account", 'activate the target SG user'),
        (102, 'Cannot sudo as target', 'check the target SG user'),
        (102, "The script does not have permission to 'sudo'", 'grant the script permission'),
        (102, "Can't authenticate script", 'check the SG script name and key'),
        (102, '', 'check the SG script name and key'),
        (100, 'unclassified', 'SG reported a server fault'),
        (106, '', 'two-factor authentication'),
        (108, '', 'single sign-on'),
        (110, '', 'Autodesk Identity'),
        (987654, 'unclassified', 'HTTP 200'),
    ],
)
def test_rpc_refusal_uses_only_local_facts(code: int, diagnosis: str, hint: str) -> None:
    marker = 'session-header-credential'
    session = requests.Session()
    session.headers['Authorization'] = marker

    def refuse(request: requests.PreparedRequest, **_kwargs: object) -> requests.Response:
        message = f'{diagnosis} {request.headers["Authorization"]}'
        body = {'exception': True, 'error_code': code, 'message': message}
        return Mock(status_code=200, json=Mock(return_value=body))

    session.send = Mock(side_effect=refuse)
    with pytest.raises(SGError) as caught:
        _minter('https://sg.example', session=session).mint_session_token('script', 'key')
    assert hint in str(caught.value)
    assert '987654' not in str(caught.value)
    assert marker not in ''.join(traceback.format_exception(caught.value))
    assert marker not in repr(vars(caught.value))


def test_site_url_refuses_embedded_credentials() -> None:
    with pytest.raises(SGError, match='script') as caught:
        _minter('https://someone:private@sg.example')
    assert 'someone' not in str(caught.value)
    assert 'private' not in str(caught.value)


def test_unsent_request_error_redacts_submitted_credential() -> None:
    credential = 'synthetic-script-credential'
    session = Mock(post=Mock(side_effect=OSError(f'local failure for {credential}')))
    with pytest.raises(SGError) as caught:
        _minter('https://sg.example', session=session).mint_rest_token('script', credential)
    assert str(caught.value).endswith('could not be sent: OSError')
    assert credential not in caught.value.audit_detail
    assert credential not in ''.join(traceback.format_exception(caught.value))
