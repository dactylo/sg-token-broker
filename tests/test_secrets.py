import base64
from pathlib import Path

import pytest

from sg_token_broker._secrets import (
    SecretError,
    generate_secret,
    hash_secret,
    parse_secret_hash,
    resolve_script_key,
    token_fingerprint,
    verify_secret,
)

_DIGEST_B64 = base64.b64encode(b'digest').decode()
_SALT_B64 = base64.b64encode(b'salt').decode()


class TestHashing:
    def test_generate_secret_is_long_and_unique(self) -> None:
        a, b = generate_secret(), generate_secret()
        assert a != b
        assert len(a) >= 32

    def test_hash_format(self) -> None:
        parts = hash_secret('s').split('$')
        assert parts[0] == 'scrypt'
        assert [int(p) for p in parts[1:4]] == [16384, 8, 1]

    def test_hashes_are_salted(self) -> None:
        assert hash_secret('s') != hash_secret('s')

    def test_malformed_digest_is_rejected_before_kdf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail_scrypt(*_args: object, **_kwargs: object) -> bytes:
            raise AssertionError('hashlib.scrypt must not be called')

        monkeypatch.setattr('sg_token_broker._secrets.hashlib.scrypt', fail_scrypt)
        bad = 'scrypt$16384$8$1$' + base64.b64encode(b's' * 16).decode() + '$AQ=='

        with pytest.raises(SecretError, match='malformed'):
            verify_secret('anything', bad)

    @pytest.mark.parametrize('bad', ['', 'scrypt$x', 'md5$1$2$3$a$b', 'scrypt$1$2$3$!!$=='])
    def test_malformed_hash_raises(self, bad: str) -> None:
        with pytest.raises(SecretError):
            verify_secret('s', bad)

    @pytest.mark.parametrize(
        'bad',
        [
            'scrypt$2$1$1$c2FsdA==$AQ==',
            'scrypt$16384$8$1$c2FsdA==$' + base64.b64encode(b'x' * 64).decode(),
            'scrypt$16384$8$1$' + base64.b64encode(b's' * 16).decode() + '$AQ==',
            'scrypt$8192$8$1$'
            + base64.b64encode(b's' * 16).decode()
            + '$'
            + base64.b64encode(b'x' * 64).decode(),
        ],
    )
    def test_non_production_parameters_are_rejected(self, bad: str) -> None:
        with pytest.raises(SecretError, match='malformed'):
            parse_secret_hash(bad)
        with pytest.raises(SecretError, match='malformed'):
            verify_secret('anything', bad)

    def test_parse_accepts_hash_secret_output(self) -> None:
        salt, digest = parse_secret_hash(hash_secret('s3cret'))
        assert len(salt) == 16
        assert len(digest) == 64

    def test_roundtrip(self) -> None:
        secret = generate_secret()
        assert verify_secret(secret, hash_secret(secret))

    @pytest.mark.parametrize(
        'bad',
        [
            f'scrypt$3$8$1${_SALT_B64}${_DIGEST_B64}',
            f'scrypt$16384$0$1${_SALT_B64}${_DIGEST_B64}',
            f'scrypt$16384$8$0${_SALT_B64}${_DIGEST_B64}',
            f'scrypt$16384$8$1$${_DIGEST_B64}',
            f'scrypt$16384$8$1${_SALT_B64}$',
        ],
        ids=['n-not-power-of-two', 'zero-r', 'zero-p', 'empty-salt', 'empty-digest'],
    )
    def test_structurally_complete_malformed_hash_raises(self, bad: str) -> None:
        with pytest.raises(SecretError, match='malformed'):
            verify_secret('s', bad)

    def test_wrong_secret_rejected(self) -> None:
        assert not verify_secret('nope', hash_secret('right'))


class TestResolveScriptKey:
    def test_empty_file_raises(self, tmp_path: Path) -> None:
        keyfile = tmp_path / 'key'
        keyfile.write_text('\n')
        with pytest.raises(SecretError, match='empty'):
            resolve_script_key(env=None, file=keyfile)

    def test_exactly_one_source_required(self, tmp_path: Path) -> None:
        with pytest.raises(SecretError):
            resolve_script_key(env=None, file=None)
        with pytest.raises(SecretError):
            resolve_script_key(env='X', file=tmp_path / 'k')

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv('SGTB_TEST_KEY', 'k123')
        assert resolve_script_key(env='SGTB_TEST_KEY', file=None) == 'k123'

    def test_from_file(self, tmp_path: Path) -> None:
        keyfile = tmp_path / 'key'
        keyfile.write_text('k456\n')
        assert resolve_script_key(env=None, file=keyfile) == 'k456'

    def test_missing_env_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv('SGTB_ABSENT', raising=False)
        with pytest.raises(SecretError, match='SGTB_ABSENT'):
            resolve_script_key(env='SGTB_ABSENT', file=None)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(SecretError):
            resolve_script_key(env=None, file=tmp_path / 'absent')

    def test_undecodable_file_raises(self, tmp_path: Path) -> None:
        keyfile = tmp_path / 'key[1]'
        keyfile.write_bytes(b'\xff')
        with pytest.raises(SecretError) as caught:
            resolve_script_key(env=None, file=keyfile)
        assert str(keyfile) in str(caught.value)


class TestTokenFingerprint:
    def test_distinct_tokens_differ(self) -> None:
        assert token_fingerprint('tok-a') != token_fingerprint('tok-b')

    def test_not_reversible_prefix(self) -> None:
        assert 'tok-a' not in token_fingerprint('tok-a')

    def test_stable_and_short(self) -> None:
        a, b = token_fingerprint('tok-a'), token_fingerprint('tok-a')
        assert a == b
        assert len(a) == 16
