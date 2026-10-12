import ipaddress

import pytest

from sg_token_broker import _userconfig
from sg_token_broker._userconfig import UserConfigError, load_user_token_config

_ENV_PREFIX = _userconfig._ENV_PREFIX

REQUIRED = ('SITE_URL', 'SCRIPT_NAME', 'SCRIPT_KEY', 'AUDIENCES', 'ALLOWED_DOMAIN')


class TestLoadUserTokenConfig:
    def test_assume_email_verified_rejects_invalid_value(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_ASSUME_EMAIL_VERIFIED': 'yes'})
        with pytest.raises(UserConfigError, match='ASSUME_EMAIL_VERIFIED'):
            load_user_token_config(env)

    def test_assume_email_verified_true(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_ASSUME_EMAIL_VERIFIED': ' TrUe '})
        assert load_user_token_config(env).assume_email_verified is True

    def test_blank_audience_list_fails(self) -> None:
        with pytest.raises(UserConfigError, match='AUDIENCES'):
            load_user_token_config(_make_env(**{f'{_ENV_PREFIX}_AUDIENCES': ' ,, '}))

    def test_custom_email_claim(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_EMAIL_CLAIM': ' subject_email '})
        assert load_user_token_config(env).email_claim == 'subject_email'

    def test_degenerate_allowed_domain_fails(self) -> None:
        with pytest.raises(UserConfigError, match='ALLOWED_DOMAIN'):
            load_user_token_config(_make_env(**{f'{_ENV_PREFIX}_ALLOWED_DOMAIN': '@'}))

    def test_degenerate_site_url_fails(self) -> None:
        with pytest.raises(UserConfigError, match='SITE_URL'):
            load_user_token_config(_make_env(**{f'{_ENV_PREFIX}_SITE_URL': '/'}))

    def test_loads_and_normalizes(self) -> None:
        config = load_user_token_config(_make_env())
        assert config.site_url == 'https://studio.example.com'
        assert config.script_name == 'user_token_service'
        assert config.audiences == ('aud-one', 'aud-two')
        assert config.allowed_domain == 'studio.example'
        assert config.port == 8080

    def test_loopback_http_site_url_is_accepted(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_SITE_URL': 'http://127.0.0.1:8080'})
        assert load_user_token_config(env).site_url == 'http://127.0.0.1:8080'

    @pytest.mark.parametrize('name', REQUIRED)
    def test_missing_variable_fails(self, name: str) -> None:
        env = _make_env()
        del env[f'{_ENV_PREFIX}_{name}']
        with pytest.raises(UserConfigError, match=name):
            load_user_token_config(env)

    def test_non_integer_port_fails(self) -> None:
        with pytest.raises(UserConfigError, match='PORT'):
            load_user_token_config({**_make_env(), 'PORT': 'web'})

    def test_non_integer_session_ttl_fails(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_SESSION_TTL_SECONDS': 'ten minutes'})
        with pytest.raises(UserConfigError, match='SESSION_TTL_SECONDS'):
            load_user_token_config(env)

    def test_oidc_accepts_custom_asymmetric_algorithms(self) -> None:
        env = _make_env(
            **{
                f'{_ENV_PREFIX}_PROVIDER': 'oidc',
                f'{_ENV_PREFIX}_ISSUER': 'https://idp.example.com',
                f'{_ENV_PREFIX}_OIDC_ALGORITHMS': 'PS512, ES384',
            }
        )
        assert load_user_token_config(env).oidc_algorithms == ('ES384', 'PS512')

    def test_oidc_algorithms_must_be_asymmetric(self) -> None:
        env = _make_env(
            **{
                f'{_ENV_PREFIX}_PROVIDER': 'oidc',
                f'{_ENV_PREFIX}_ISSUER': 'https://idp.example.com',
                f'{_ENV_PREFIX}_OIDC_ALGORITHMS': 'HS256',
            }
        )
        with pytest.raises(UserConfigError, match='HS256'):
            load_user_token_config(env)

    @pytest.mark.parametrize(
        'issuer', ['https://idp.example.com/tenant/', 'http://127.0.0.1:8080/issuer/']
    )
    def test_oidc_issuer_is_preserved(self, issuer: str) -> None:
        env = _make_env(
            **{
                f'{_ENV_PREFIX}_PROVIDER': 'oidc',
                f'{_ENV_PREFIX}_ISSUER': issuer,
            }
        )
        config = load_user_token_config(env)
        assert config.provider == 'oidc'
        assert config.issuer == issuer

    def test_oidc_issuer_requires_https(self) -> None:
        env = _make_env(
            **{
                f'{_ENV_PREFIX}_PROVIDER': 'oidc',
                f'{_ENV_PREFIX}_ISSUER': 'http://idp.example.com',
            }
        )
        with pytest.raises(UserConfigError, match='ISSUER'):
            load_user_token_config(env)

    def test_oidc_provider_requires_issuer(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_PROVIDER': 'oidc'})
        with pytest.raises(UserConfigError, match='ISSUER'):
            load_user_token_config(env)

    @pytest.mark.parametrize('port', ['0', '70000'])
    def test_out_of_range_port_fails(self, port: str) -> None:
        with pytest.raises(UserConfigError, match='PORT'):
            load_user_token_config({**_make_env(), 'PORT': port})

    def test_port_override(self) -> None:
        assert load_user_token_config({**_make_env(), 'PORT': '9000'}).port == 9000

    def test_remote_http_site_url_fails(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_SITE_URL': 'http://sg.studio.internal'})
        with pytest.raises(UserConfigError, match='SITE_URL'):
            load_user_token_config(env)

    def test_repr_hides_the_script_key(self) -> None:
        assert 'svc-credential' not in repr(load_user_token_config(_make_env()))

    def test_schemeless_site_url_fails(self) -> None:
        with pytest.raises(UserConfigError, match='SITE_URL'):
            load_user_token_config(_make_env(**{f'{_ENV_PREFIX}_SITE_URL': 'studio.example.com'}))

    def test_session_defaults(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_TOKEN_TYPES': 'session,rest'})
        config = load_user_token_config(env)
        assert config.token_types == frozenset({'session', 'rest'})
        assert config.session_ttl_seconds == 600
        assert config.trusted_proxies == frozenset()
        assert config.provider == 'google'
        assert config.email_claim == 'email'
        assert config.assume_email_verified is False
        assert config.oidc_algorithms == ('ES256', 'RS256')

    @pytest.mark.parametrize('ttl', ['0', '-1'])
    def test_session_ttl_must_be_positive(self, ttl: str) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_SESSION_TTL_SECONDS': ttl})
        with pytest.raises(UserConfigError, match='SESSION_TTL_SECONDS'):
            load_user_token_config(env)

    def test_session_ttl_override(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_SESSION_TTL_SECONDS': '42'})
        assert load_user_token_config(env).session_ttl_seconds == 42

    def test_token_types_is_required(self) -> None:
        env = _make_env()
        del env[f'{_ENV_PREFIX}_TOKEN_TYPES']
        with pytest.raises(UserConfigError, match='TOKEN_TYPES'):
            load_user_token_config(env)

    def test_token_types_rejects_unknown_values(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_TOKEN_TYPES': 'rest,bearer'})
        with pytest.raises(UserConfigError, match='bearer'):
            load_user_token_config(env)

    def test_trusted_proxies_are_canonical_addresses(self) -> None:
        config = load_user_token_config(
            _make_env(
                SGUT_TRUSTED_PROXIES=('2001:0db8:0000:0000:0000:0000:0000:0001, ::ffff:10.0.0.1')
            )
        )
        assert config.trusted_proxies == frozenset(
            {ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('10.0.0.1')}
        )

    def test_trusted_proxies_parse(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_TRUSTED_PROXIES': '10.0.0.1, 10.0.0.2'})
        config = load_user_token_config(env)
        assert config.trusted_proxies == frozenset(
            {ipaddress.ip_address('10.0.0.1'), ipaddress.ip_address('10.0.0.2')}
        )

    def test_trusted_proxies_reject_invalid_ip(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_TRUSTED_PROXIES': '10.0.0.999'})
        with pytest.raises(UserConfigError) as exc_info:
            load_user_token_config(env)
        assert str(exc_info.value) == (
            "SGUT_TRUSTED_PROXIES entry is not an IP address: '10.0.0.999'"
        )
        assert isinstance(exc_info.value.__cause__, ValueError)

    def test_unknown_provider_fails(self) -> None:
        env = _make_env(**{f'{_ENV_PREFIX}_PROVIDER': 'azure'})
        with pytest.raises(UserConfigError, match='azure'):
            load_user_token_config(env)


def _make_env(**overrides: str) -> dict[str, str]:
    env = {
        f'{_ENV_PREFIX}_SITE_URL': 'https://studio.example.com/',
        f'{_ENV_PREFIX}_SCRIPT_NAME': 'user_token_service',
        f'{_ENV_PREFIX}_SCRIPT_KEY': 'svc-credential',
        f'{_ENV_PREFIX}_AUDIENCES': ' aud-one ,aud-two, ',
        f'{_ENV_PREFIX}_ALLOWED_DOMAIN': '@Studio.Example',
        f'{_ENV_PREFIX}_TOKEN_TYPES': 'rest',
    }
    env.update(overrides)
    return env
