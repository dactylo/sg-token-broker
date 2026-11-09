"""Load and validate broker YAML configuration."""

import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

import yaml

from sg_token_broker._secrets import SecretError, parse_secret_hash
from sg_token_broker._urlpolicy import is_loopback_host, require_https_or_loopback

CLIENT_ID_MAX_CHARS = 64

_CLIENT_KEYS = frozenset({'rate_limit_per_minute', 'scopes', 'secret_hash', 'token_types'})
_DEFAULTS_KEYS = frozenset({'rate_limit_per_minute', 'session_ttl_seconds', 'token_types'})
_DEFAULT_PORT = 8743
_DEFAULT_RATE_LIMIT_PER_MINUTE = 60
_DEFAULT_SESSION_TTL_SECONDS = 600
_MAX_PORT = 65535
_ROOT_KEYS = frozenset({'clients', 'defaults', 'scopes', 'server', 'site_url'})
_SCOPE_KEYS = frozenset({'script_key_env', 'script_key_file', 'script_name'})
_SERVER_KEYS = frozenset({'bind', 'port', 'tls'})
_TLS_KEYS = frozenset({'cert_file', 'key_file'})
_TOKEN_TYPES = frozenset({'rest', 'session'})


@dataclass(frozen=True)
class _ClientConfig:
    """Configure one broker client."""

    # secret_hash contains a validated serialized scrypt hash.
    client_id: str
    secret_hash: str
    scopes: frozenset[str]
    rate_limit_per_minute: int
    token_types: frozenset[str]


class ConfigError(Exception):
    """The broker configuration file is missing, malformed, or invalid."""


@dataclass(frozen=True)
class ScopeConfig:
    """Configure a named scope backed by one SG ApiUser.

    Attributes:
        script_name: SG ApiUser script name.
        script_key_env: Optional environment variable containing the script
            key; `None` when `script_key_file` is configured.
        script_key_file: Optional file containing the script key; `None` when
            `script_key_env` is configured.
    """

    script_name: str
    script_key_env: str | None
    script_key_file: Path | None


@dataclass(frozen=True)
class _TlsConfig:
    """Configure a TLS certificate and key pair."""

    cert_file: Path
    key_file: Path


@dataclass(frozen=True)
class _ServerConfig:
    """Configure the broker listening socket."""

    bind: str
    port: int
    tls: _TlsConfig | None


@dataclass(frozen=True)
class BrokerConfig:
    """Contain the validated broker configuration.

    Attributes:
        site_url: Base URL of the SG site.
        server: Listening socket configuration.
        session_ttl_seconds: Session-token cache lifetime in seconds, also
            reported as the advisory client refresh interval. It does not
            impose an SG session expiration.
        scopes: Scope configurations keyed by scope name.
        clients: Client configurations keyed by client identifier.
    """

    site_url: str
    server: _ServerConfig
    session_ttl_seconds: int
    scopes: Mapping[str, ScopeConfig]
    clients: Mapping[str, _ClientConfig]


def _describe_yaml_error(path: Path, error: yaml.MarkedYAMLError) -> str:
    """Describe a YAML syntax error on one line with its position in the file."""
    reason = error.problem or error.context or 'syntax error'
    mark = error.problem_mark or error.context_mark
    if mark is None:
        return f'invalid YAML in {path}: {reason}'
    return f'invalid YAML in {path} at line {mark.line + 1}, column {mark.column + 1}: {reason}'


def _parse_token_types(node: object, where: str) -> frozenset[str]:
    """Validate a non-empty list of known token types."""
    values = cast('list[object]', node) if isinstance(node, list) else []
    if not values or not all(isinstance(value, str) and value in _TOKEN_TYPES for value in values):
        raise ConfigError(f'{where} must be a non-empty list of token types: rest, session')
    return frozenset(cast('list[str]', values))


def _reject_unknown_keys(data: Mapping[str, object], where: str, known: frozenset[str]) -> None:
    """Raise ConfigError listing each key outside known as a path under where."""
    unknown = sorted(set(data) - known)
    if unknown:
        noun = 'key' if len(unknown) == 1 else 'keys'
        paths = ', '.join(f'{where}.{key}' if where else key for key in unknown)
        raise ConfigError(f'unknown config {noun}: {paths}')


def _require_mapping(node: object, where: str) -> dict[str, object]:
    """Return node as a string-keyed dict or raise ConfigError naming the location."""
    if not isinstance(node, dict):
        raise ConfigError(f'{where} must be a mapping')
    fields = cast('dict[object, object]', node)
    if not all(isinstance(key, str) for key in fields):
        raise ConfigError(f'{where} keys must be strings')
    return cast('dict[str, object]', fields)


def _parse_scope(name: str, node: object) -> ScopeConfig:
    """Validate and build one ScopeConfig."""
    data = _require_mapping(node, f'scopes.{name}')
    _reject_unknown_keys(data, f'scopes.{name}', _SCOPE_KEYS)
    script_name = data.get('script_name')
    if not isinstance(script_name, str) or not script_name:
        raise ConfigError(f'scopes.{name}.script_name is required')
    env = data.get('script_key_env')
    file_ = data.get('script_key_file')
    if (env is None) == (file_ is None):
        raise ConfigError(f'scopes.{name}: exactly one of script_key_env/script_key_file required')
    if env is not None and (not isinstance(env, str) or not env):
        raise ConfigError(f'scopes.{name}.script_key_env must be a non-empty string')
    if file_ is not None and (not isinstance(file_, str) or not file_):
        raise ConfigError(f'scopes.{name}.script_key_file must be a non-empty string')
    return ScopeConfig(
        script_name=script_name,
        script_key_env=env,
        script_key_file=Path(file_) if file_ is not None else None,
    )


def _parse_server(node: object) -> _ServerConfig:
    """Validate and build the _ServerConfig, enforcing the loopback/TLS rule."""
    data = _require_mapping(node, 'server') if node is not None else {}
    _reject_unknown_keys(data, 'server', _SERVER_KEYS)
    bind = data.get('bind', '127.0.0.1')
    if not isinstance(bind, str) or not bind:
        raise ConfigError('server.bind must be a non-empty string')
    port = data.get('port', _DEFAULT_PORT)
    if type(port) is not int or not 0 <= port <= _MAX_PORT:
        raise ConfigError(f'server.port must be an int in 0..{_MAX_PORT}')
    tls: _TlsConfig | None = None
    if 'tls' in data:
        tls_data = _require_mapping(data['tls'], 'server.tls')
        _reject_unknown_keys(tls_data, 'server.tls', _TLS_KEYS)
        cert_file = tls_data.get('cert_file')
        key_file = tls_data.get('key_file')
        if not isinstance(cert_file, str) or not cert_file:
            raise ConfigError('server.tls.cert_file must be a non-empty string')
        if not isinstance(key_file, str) or not key_file:
            raise ConfigError('server.tls.key_file must be a non-empty string')
        cert = Path(cert_file)
        key = Path(key_file)
        if not cert.is_file():
            raise ConfigError(f'server.tls.cert_file not found: {cert}')
        if not key.is_file():
            raise ConfigError(f'server.tls.key_file not found: {key}')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            context.load_cert_chain(certfile=cert, keyfile=key)
        except (ssl.SSLError, OSError) as exc:
            raise ConfigError(f'server.tls certificate/key pair cannot be loaded: {exc}') from exc
        tls = _TlsConfig(cert_file=cert, key_file=key)
    if tls is None and not is_loopback_host(bind):
        raise ConfigError(
            f'refusing plain HTTP on non-loopback bind {bind!r}; configure server.tls (TLS)'
        )
    return _ServerConfig(bind=bind, port=port, tls=tls)


def is_credential_text(value: str) -> bool:
    """Return True if `value` is non-empty and every character is in 0x21-0x7E.

    Args:
        value: A client id or client secret.

    Returns:
        Whether the value fits in one Basic-auth header without encoding
        ambiguity (printable ASCII, no space).
    """
    return bool(value) and all('!' <= char <= '~' for char in value)


def is_client_id(value: str) -> bool:
    """Return True for a client id that fits the portable Basic-auth grammar.

    Args:
        value: Client identifier to validate.

    Returns:
        Whether the value has 1-64 printable ASCII characters without space or
        colon.
    """
    return is_credential_text(value) and ':' not in value and len(value) <= CLIENT_ID_MAX_CHARS


def _parse_client(
    client_id: object,
    node: object,
    scopes: Mapping[str, ScopeConfig],
    default_rate: int,
    default_types: frozenset[str],
) -> _ClientConfig:
    """Validate and build one _ClientConfig against the known scopes."""
    if not isinstance(client_id, str) or not is_client_id(client_id):
        raise ConfigError(
            f'client id must be 1..{CLIENT_ID_MAX_CHARS} printable ASCII characters '
            f'with no colon or space: {client_id!r}'
        )
    data = _require_mapping(node, f'clients.{client_id}')
    _reject_unknown_keys(data, f'clients.{client_id}', _CLIENT_KEYS)
    secret_hash = data.get('secret_hash')
    if not isinstance(secret_hash, str):
        raise ConfigError(f'clients.{client_id}.secret_hash is required')
    try:
        parse_secret_hash(secret_hash)
    except SecretError as exc:
        raise ConfigError(f'clients.{client_id}.secret_hash is malformed') from exc
    raw_scopes = data.get('scopes')
    if not isinstance(raw_scopes, list) or not raw_scopes:
        raise ConfigError(f'clients.{client_id}.scopes must be a non-empty list')
    scope_names: list[str] = []
    for scope in cast('list[object]', raw_scopes):
        if not isinstance(scope, str) or scope not in scopes:
            raise ConfigError(f'clients.{client_id} references unknown scope {scope!r}')
        scope_names.append(scope)
    rate = data.get('rate_limit_per_minute', default_rate)
    if type(rate) is not int or rate < 1:
        raise ConfigError(f'clients.{client_id}.rate_limit_per_minute must be a positive int')
    token_types = (
        _parse_token_types(data['token_types'], f'clients.{client_id}.token_types')
        if 'token_types' in data
        else default_types
    )
    return _ClientConfig(
        client_id=client_id,
        secret_hash=secret_hash,
        scopes=frozenset(scope_names),
        rate_limit_per_minute=rate,
        token_types=token_types,
    )


def load_config(path: Path) -> BrokerConfig:
    """Load and validate the broker configuration file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        The validated configuration.

    Raises:
        ConfigError: If the file is missing, malformed, or fails validation.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f'cannot read config file {path}: {exc}') from exc
    except yaml.MarkedYAMLError as exc:
        raise ConfigError(_describe_yaml_error(path, exc)) from exc
    except (yaml.YAMLError, ValueError) as exc:
        raise ConfigError(f'invalid YAML in {path}') from exc
    data = _require_mapping(raw, 'config root')
    _reject_unknown_keys(data, '', _ROOT_KEYS)

    site_url = data.get('site_url')
    if not isinstance(site_url, str):
        raise ConfigError('site_url must be an https URL string')
    try:
        require_https_or_loopback(site_url, 'site_url')
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    defaults = _require_mapping(data.get('defaults', {}), 'defaults')
    _reject_unknown_keys(defaults, 'defaults', _DEFAULTS_KEYS)
    ttl = defaults.get('session_ttl_seconds', _DEFAULT_SESSION_TTL_SECONDS)
    if type(ttl) is not int or ttl < 1:
        raise ConfigError('defaults.session_ttl_seconds must be a positive int')
    default_rate = defaults.get('rate_limit_per_minute', _DEFAULT_RATE_LIMIT_PER_MINUTE)
    if type(default_rate) is not int or default_rate < 1:
        raise ConfigError('defaults.rate_limit_per_minute must be a positive int')
    default_types = (
        _parse_token_types(defaults['token_types'], 'defaults.token_types')
        if 'token_types' in defaults
        else _TOKEN_TYPES
    )

    scope_nodes = _require_mapping(data.get('scopes'), 'scopes')
    scopes = {name: _parse_scope(name, node) for name, node in scope_nodes.items()}
    if not scopes:
        raise ConfigError('at least one scope is required')

    client_nodes = _require_mapping(data.get('clients'), 'clients')
    clients = {
        cid: _parse_client(cid, node, scopes, default_rate, default_types)
        for cid, node in client_nodes.items()
    }
    if not clients:
        raise ConfigError('at least one client is required')

    return BrokerConfig(
        site_url=site_url.rstrip('/'),
        server=_parse_server(data.get('server')),
        session_ttl_seconds=ttl,
        scopes=MappingProxyType(scopes),
        clients=MappingProxyType(clients),
    )
