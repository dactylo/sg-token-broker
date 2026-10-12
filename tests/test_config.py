import json
from pathlib import Path

import pytest

from sg_token_broker._config import ConfigError, load_config
from tests._tls import _write_tls_material

VALID = """
site_url: https://studio.shotgunstudio.com
server:
  bind: 127.0.0.1
  port: 8743
defaults:
  session_ttl_seconds: 300
  rate_limit_per_minute: 30
scopes:
  read_all:
    script_name: broker_read_all
    script_key_env: SGTB_KEY_READ_ALL
clients:
  farm:
    secret_hash: "{h}"
    scopes: [read_all]
"""
# Precomputed valid hash; configuration parsing does not derive credentials.
_VALID_HASH = (
    'scrypt$16384$8$1$tvgu3S28sX35pfwGM4X15A==$'
    'eIy4ZbBCDrTwa1WOeMsXcrN+zdAPoOSK5/2nkjOTGwwBo+j3pzLXHHPaiQLOf+xay8OGpCAFvkgC4Z+WyA/ziA=='
)


class TestLoadConfig:
    def test_bad_hash_rejected(self, tmp_path: Path) -> None:
        text = VALID.format(h='plaintext-oops')
        with pytest.raises(ConfigError, match='secret_hash'):
            load_config(_write(tmp_path, text))

    def test_bad_site_url_rejected(self, tmp_path: Path) -> None:
        text = _valid_text().replace('https://studio.shotgunstudio.com', 'ftp://x')
        with pytest.raises(ConfigError, match='site_url'):
            load_config(_write(tmp_path, text))

    @pytest.mark.parametrize('client_id', ['', 'a:b', 'café', 'x' * 65, 'tab\there', 'with space'])
    def test_client_id_grammar(self, tmp_path: Path, client_id: str) -> None:
        text = _valid_text().replace('  farm:', f'  {json.dumps(client_id)}:', 1)
        with pytest.raises(ConfigError, match='client id must be'):
            load_config(_write(tmp_path, text))

    def test_defaults_applied(self, tmp_path: Path) -> None:
        text = _valid_text().replace(
            'defaults:\n  session_ttl_seconds: 300\n  rate_limit_per_minute: 30\n', ''
        )
        cfg = load_config(_write(tmp_path, text))
        assert cfg.session_ttl_seconds == 600
        assert cfg.clients['farm'].rate_limit_per_minute == 60

    def test_loopback_http_site_url_accepted(self, tmp_path: Path) -> None:
        text = _valid_text().replace('https://studio.shotgunstudio.com', 'http://127.0.0.1:8888')
        assert load_config(_write(tmp_path, text)).site_url == 'http://127.0.0.1:8888'

    def test_loopback_ipv6_without_tls_accepted(self, tmp_path: Path) -> None:
        text = _valid_text().replace('bind: 127.0.0.1', 'bind: "::1"')
        config = load_config(_write(tmp_path, text))
        assert config.server.bind == '::1'
        assert config.server.tls is None

    def test_malformed_scrypt_hash_rejected(self, tmp_path: Path) -> None:
        text = VALID.format(h='scrypt$3$8$1$c2FsdA==$ZGlnZXN0')
        with pytest.raises(ConfigError, match='secret_hash'):
            load_config(_write(tmp_path, text))

    @pytest.mark.parametrize(
        ('old', 'new', 'where'),
        [('  read_all:', '  7:', 'scopes'), ('  farm:', '  7:', 'clients')],
    )
    def test_mapping_keys_must_be_strings(
        self, tmp_path: Path, old: str, new: str, where: str
    ) -> None:
        text = _valid_text().replace(old, new, 1)
        with pytest.raises(ConfigError, match=rf'{where} keys must be strings'):
            load_config(_write(tmp_path, text))

    def test_mismatched_tls_pair_is_a_config_error(self, tmp_path: Path) -> None:
        directory_a = tmp_path / 'a'
        directory_a.mkdir()
        cert_a, _ = _write_tls_material(directory_a)
        directory_b = tmp_path / 'b'
        directory_b.mkdir()
        _, key_b = _write_tls_material(directory_b)
        text = _valid_text().replace(
            'server:\n',
            f'server:\n  bind: 0.0.0.0\n  tls:\n    cert_file: {cert_a}\n    key_file: {key_b}\n',
            1,
        )
        with pytest.raises(ConfigError, match=r'server\.tls'):
            load_config(_write(tmp_path, text))

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(tmp_path / 'absent.yml')

    def test_no_clients_rejected(self, tmp_path: Path) -> None:
        text = _valid_text().split('clients:')[0] + 'clients: {}\n'
        with pytest.raises(ConfigError, match='client'):
            load_config(_write(tmp_path, text))

    @pytest.mark.parametrize('host', ['10.1.2.3', '2001:db8::1'])
    def test_non_loopback_without_tls_rejected(self, tmp_path: Path, host: str) -> None:
        text = _valid_text().replace('bind: 127.0.0.1', f'bind: "{host}"')
        with pytest.raises(ConfigError, match='TLS'):
            load_config(_write(tmp_path, text))

    def test_non_utf8_config_is_a_config_error(self, tmp_path: Path) -> None:
        path = tmp_path / 'broker.yml'
        path.write_bytes(b'# caf\xe9\n' + _valid_text().encode())
        with pytest.raises(ConfigError, match='cannot read config file'):
            load_config(path)

    def test_remote_http_site_url_rejected(self, tmp_path: Path) -> None:
        text = _valid_text().replace(
            'https://studio.shotgunstudio.com', 'http://sg.studio.internal'
        )
        with pytest.raises(ConfigError, match='site_url'):
            load_config(_write(tmp_path, text))

    @pytest.mark.parametrize(
        ('field', 'value'),
        [
            ('script_key_env', "''"),
            ('script_key_env', '42'),
            ('script_key_file', "''"),
            ('script_key_file', '42'),
        ],
    )
    def test_scope_key_source_must_be_non_empty_string(
        self, tmp_path: Path, field: str, value: str
    ) -> None:
        text = _valid_text().replace(
            'script_key_env: SGTB_KEY_READ_ALL',
            f'{field}: {value}',
        )
        with pytest.raises(ConfigError, match=rf'scopes\.read_all\.{field}'):
            load_config(_write(tmp_path, text))

    def test_scope_needs_exactly_one_key_source(self, tmp_path: Path) -> None:
        text = _valid_text().replace(
            'script_key_env: SGTB_KEY_READ_ALL',
            'script_key_env: A\n    script_key_file: /b',
        )
        with pytest.raises(ConfigError, match='script_key'):
            load_config(_write(tmp_path, text))

    def test_tls_files_must_exist(self, tmp_path: Path) -> None:
        text = _valid_text().replace(
            'server:\n  bind: 127.0.0.1\n  port: 8743\n',
            'server:\n  bind: 127.0.0.1\n  port: 8743\n  tls:\n'
            '    cert_file: /no/cert.pem\n    key_file: /no/key.pem\n',
        )
        with pytest.raises(ConfigError, match='cert'):
            load_config(_write(tmp_path, text))

    def test_unknown_scope_in_client_rejected(self, tmp_path: Path) -> None:
        text = _valid_text().replace('scopes: [read_all]', 'scopes: [nope]')
        with pytest.raises(ConfigError, match='nope'):
            load_config(_write(tmp_path, text))

    def test_unyamlish_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(_write(tmp_path, '{nope'))

    def test_uppercase_localhost_is_loopback(self, tmp_path: Path) -> None:
        text = _valid_text().replace('bind: 127.0.0.1', 'bind: LOCALHOST', 1)
        assert load_config(_write(tmp_path, text)).server.bind == 'LOCALHOST'

    def test_valid(self, tmp_path: Path) -> None:
        cfg = load_config(_write(tmp_path, _valid_text()))
        assert cfg.site_url == 'https://studio.shotgunstudio.com'
        assert cfg.server.port == 8743
        assert cfg.session_ttl_seconds == 300
        assert cfg.scopes['read_all'].script_name == 'broker_read_all'
        assert cfg.clients['farm'].scopes == frozenset({'read_all'})
        assert cfg.clients['farm'].rate_limit_per_minute == 30

    def test_valid_config_does_not_run_kdf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        text = _valid_text()

        def fail_scrypt(*_args: object, **_kwargs: object) -> bytes:
            raise AssertionError('hashlib.scrypt must not be called')

        monkeypatch.setattr('sg_token_broker._secrets.hashlib.scrypt', fail_scrypt)

        assert load_config(_write(tmp_path, text)).clients['farm'].client_id == 'farm'

    def test_weak_secret_hash_is_rejected(self, tmp_path: Path) -> None:
        text = VALID.format(h='scrypt$2$1$1$c2FsdA==$AQ==')
        with pytest.raises(ConfigError, match='secret_hash is malformed'):
            load_config(_write(tmp_path, text))

    @pytest.mark.parametrize(
        ('needle', 'replacement', 'message'),
        [
            ('port: 8743', 'port: on', 'server.port'),
            ('session_ttl_seconds: 300', 'session_ttl_seconds: yes', 'session_ttl_seconds'),
            ('rate_limit_per_minute: 30', 'rate_limit_per_minute: true', 'rate_limit_per_minute'),
            (
                '    scopes: [read_all]',
                '    scopes: [read_all]\n    rate_limit_per_minute: yes',
                'clients.farm.rate_limit_per_minute',
            ),
        ],
    )
    def test_yaml_booleans_are_not_integers(
        self, tmp_path: Path, needle: str, replacement: str, message: str
    ) -> None:
        text = _valid_text()
        assert needle in text
        with pytest.raises(ConfigError, match=message):
            load_config(_write(tmp_path, text.replace(needle, replacement, 1)))


def _valid_text() -> str:
    return VALID.format(h=_VALID_HASH)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / 'broker.yml'
    path.write_text(text)
    return path
