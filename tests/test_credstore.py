import pytest

from sg_token_broker import _credstore
from sg_token_broker._credstore import (
    delete_account,
    delete_refresh_token,
    load_account,
    load_refresh_token,
    store_account,
    store_refresh_token,
)


class _KeyringError(Exception):
    pass


class _MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password


class _PasswordDeleteError(_KeyringError):
    pass


class _FakeErrors:
    KeyringError = _KeyringError
    PasswordDeleteError = _PasswordDeleteError


class _FakeKeyringModule:
    errors = _FakeErrors()

    def __init__(self) -> None:
        self.backend: object = _MemoryKeyring()

    def get_keyring(self) -> object:
        return self.backend


class TestCredStore:
    def test_account_pointer_round_trip(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _MemoryKeyring()
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        assert store_account('https://idp', 'client-1', 'jane@s.example')
        assert load_account('https://idp', 'client-1') == 'jane@s.example'
        assert delete_account('https://idp', 'client-1') is True
        assert load_account('https://idp', 'client-1') is None

    def test_backend_errors_degrade_instead_of_raising(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        class _BrokenKeyring(_MemoryKeyring):
            def get_password(self, service: str, username: str) -> str | None:
                del service, username
                raise keyring.errors.KeyringError('vault locked')

        backend = _BrokenKeyring()
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        assert load_refresh_token('https://idp', 'c', 'a') is None

    def test_delete_backend_error_returns_false(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        class BrokenDeleteKeyring(_MemoryKeyring):
            def delete_password(self, service: str, username: str) -> None:
                del service, username
                raise keyring.errors.KeyringError('vault locked')

        backend = BrokenDeleteKeyring()
        backend.values[('sg-token-broker|https://idp|c', 'a')] = 'rt-1'
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        assert delete_refresh_token('https://idp', 'c', 'a') is False

    def test_delete_missing_entry_is_success(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        class MissingKeyring(_MemoryKeyring):
            def delete_password(self, service: str, username: str) -> None:
                del service, username
                raise AssertionError('delete should not run for an absent entry')

        backend = MissingKeyring()
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        assert delete_refresh_token('https://idp', 'c', 'a') is True

    def test_entries_are_namespaced(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _MemoryKeyring()
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        store_refresh_token('https://idp-a', 'client-1', 'jane', 'rt-a')
        store_refresh_token('https://idp-b', 'client-1', 'jane', 'rt-b')
        assert load_refresh_token('https://idp-a', 'client-1', 'jane') == 'rt-a'
        assert load_refresh_token('https://idp-b', 'client-1', 'jane') == 'rt-b'

    def test_password_delete_error_returns_false(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        class FailedDeleteKeyring(_MemoryKeyring):
            def delete_password(self, service: str, username: str) -> None:
                del service, username
                raise keyring.errors.PasswordDeleteError('keychain rejected deletion')

        backend = FailedDeleteKeyring()
        backend.values[('sg-token-broker|https://idp|c', 'a')] = 'rt-1'
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        assert delete_refresh_token('https://idp', 'c', 'a') is False

    def test_round_trip_with_approved_backend(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _MemoryKeyring()
        keyring.backend = backend
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)
        assert store_refresh_token('https://idp', 'client-1', 'jane@s.example', 'rt-1')
        assert load_refresh_token('https://idp', 'client-1', 'jane@s.example') == 'rt-1'
        assert delete_refresh_token('https://idp', 'client-1', 'jane@s.example') is True
        assert load_refresh_token('https://idp', 'client-1', 'jane@s.example') is None

    def test_secure_backend_write_error_returns_false(
        self, keyring: _FakeKeyringModule, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        class _BrokenWriteKeyring(_MemoryKeyring):
            def set_password(self, service: str, username: str, password: str) -> None:
                del service, username, password
                raise keyring.errors.KeyringError('vault locked')

        keyring.backend = _BrokenWriteKeyring()
        monkeypatch.setattr(_credstore, '_backend_is_secure', _secure)

        assert store_refresh_token('https://idp', 'c', 'a', 'rt-1') is False

    def test_unapproved_backend_degrades_to_no_store(self, keyring: _FakeKeyringModule) -> None:
        backend = _MemoryKeyring()
        keyring.backend = backend
        assert store_refresh_token('https://idp', 'c', 'a', 'rt-1') is False
        assert backend.values == {}

    def test_unapproved_backend_never_supplies_credentials(
        self, keyring: _FakeKeyringModule
    ) -> None:
        backend = _MemoryKeyring()
        backend.values[('sg-token-broker|https://idp|c', 'a')] = 'rt-1'
        keyring.backend = backend
        assert load_refresh_token('https://idp', 'c', 'a') is None


def _secure(_backend: object) -> bool:
    return True


@pytest.fixture(autouse=True)
def keyring(monkeypatch: pytest.MonkeyPatch) -> _FakeKeyringModule:
    fake = _FakeKeyringModule()
    real_import_module = _credstore.importlib.import_module

    def import_module(name: str, package: str | None = None) -> object:
        if name == 'keyring':
            return fake
        return real_import_module(name, package)

    monkeypatch.setattr(_credstore.importlib, 'import_module', import_module)
    return fake


def test_missing_keyring_degrades_every_operation(monkeypatch: pytest.MonkeyPatch) -> None:

    def missing(name: str) -> object:
        assert name == 'keyring'
        raise ImportError(name)

    monkeypatch.setattr(_credstore.importlib, 'import_module', missing)

    assert load_account('https://idp', 'client-1') is None
    assert load_refresh_token('https://idp', 'client-1', 'account') is None
    assert not store_account('https://idp', 'client-1', 'account')
    assert not store_refresh_token('https://idp', 'client-1', 'account', 'credential')
    assert not delete_account('https://idp', 'client-1')
    assert not delete_refresh_token('https://idp', 'client-1', 'account')


@pytest.mark.parametrize(
    ('module', 'name'),
    [
        ('keyring.backends.macOS', 'Keyring'),
        ('keyring.backends.SecretService', 'Keyring'),
        ('keyring.backends.Windows', 'WinVaultKeyring'),
    ],
)
def test_secure_backend_allowlist_accepts_supported_identity(
    module: str,
    name: str,
) -> None:
    backend_type = type(name, (), {'__module__': module})

    assert _credstore._backend_is_secure(backend_type()) is True


def test_secure_backend_allowlist_rejects_memory_backend() -> None:
    assert _credstore._backend_is_secure(_MemoryKeyring()) is False
