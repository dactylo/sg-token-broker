import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from sg_token_broker._audit import AuditLogger
from sg_token_broker._cache import TTLCache
from sg_token_broker._config import load_config
from sg_token_broker._http import create_server
from sg_token_broker._service import BrokerService
from sg_token_broker._sg import SGMinter

_API_USER_ENTITY: dict[str, object] = {'type': 'ApiUser', 'id': 2442, 'name': 'fake_script'}
BROKER_CREDENTIAL = 'farm-credential'
# Precomputed hash of BROKER_CREDENTIAL; authentication still uses the real KDF.
BROKER_HASH = (
    'scrypt$16384$8$1$tcz9OTN0w9hLf2Zh12rdKQ==$'
    'awBt8momr/VzxYTd7/N+PmovkQUbLjh48W5GCf/2yUlprwvi/nWejmNmwCWgsPo5wy/dsyY/b6t/DCDF6l1C3Q=='
)


@dataclass
class FakeSG:
    url: str = ''
    canned_session: str = 'sess-token-1'
    canned_rest: str = 'rest-token-1'
    fail_rpc: bool = False
    fail_rest: bool = False
    rest_non_json: bool = False
    session_revoked: bool = False
    weird_json: bool = False
    nested_results: bool = False
    rpc_results_as_list: bool = False
    # REST sudo simulation knobs.
    disabled_login: str = ''
    dead_bearers: list[str] = field(default_factory=list[str])
    plain_project_count: int = 5
    sudo_project_count: int = 2
    rest_scopes: list[str] = field(default_factory=list[str])
    # User-token service simulation knobs.
    known_emails: dict[str, str] = field(default_factory=dict[str, str])
    fail_user_lookup: bool = False
    duplicate_email: str = ''
    rest_expires_in: int = 600
    rest_failure_title: str = 'Authentication failed'
    rest_failure_status: int = 401
    rest_credentials: dict[str, str] = field(default_factory=dict[str, str])
    requests: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    # Probe-classification knobs.
    rpc_fault: bool = False
    rpc_missing_session_id: bool = False
    rpc_error_code_override: object | None = None
    rpc_session_id_override: str | None = None
    rpc_status_override: int | None = None
    fail_entities_status: int = 0
    entities_non_json: bool = False
    bogus_sudo_failure_status: int = 0
    # Human-session probe simulation knobs.
    human_logins: dict[str, int] = field(default_factory=dict[str, int])
    human_permission_roles: dict[str, tuple[int, str]] = field(
        default_factory=dict[str, tuple[int, str]]
    )
    human_project_counts: dict[str, int] = field(default_factory=dict[str, int])
    rpc_api_users: dict[str, tuple[int, int, str]] = field(
        default_factory=dict[str, tuple[int, int, str]]
    )
    rpc_script_sessions: dict[str, dict[str, object]] = field(
        default_factory=dict[str, dict[str, object]]
    )
    rpc_sudo_enabled_scripts: set[str] = field(default_factory=set[str])
    rpc_sudo_mint_failures: dict[tuple[str, str], dict[str, object]] = field(
        default_factory=dict[tuple[str, str], dict[str, object]]
    )
    human_password: str = field(default='pw', repr=False)
    web_sessions: dict[str, str] = field(default_factory=dict[str, str])
    rpc_human_sudo_mode: str = 'reject'
    sudo_ignored: bool = False
    rpc_mint_identity_override: dict[str, object] | None = None
    rpc_permission_matrix_counts: dict[tuple[str, int, str], int] = field(
        default_factory=dict[tuple[str, int, str], int]
    )
    rpc_permission_matrix_responses: dict[
        tuple[str, int, str],
        dict[str, object],
    ] = field(default_factory=dict[tuple[str, int, str], dict[str, object]])
    rpc_sudo_mint_identity_override: dict[str, object] | None = None
    rpc_read_entities_override: object | None = None
    rpc_human_delete_forbidden: bool = False
    rpc_disabled_human_read_error_code: object | None = None
    rpc_disabled_human_sessions_work: bool = False
    disabled_human_sessions: set[str] = field(default_factory=set[str])
    human_session_serial: int = 0
    issued_human_sessions: set[str] = field(default_factory=set[str])
    rpc_human_renewed_session: str = ''
    rpc_known_human_sessions_stay_dead: bool = False
    rpc_unique_human_sessions: bool = False
    rpc_idle_window_seconds: float | None = None
    rpc_now: float = 0.0
    rpc_session_last_activity: dict[str, float] = field(default_factory=dict[str, float])
    rpc_create_response_overrides: list[tuple[int, dict[str, object]] | None] = field(
        default_factory=list[tuple[int, dict[str, object]] | None]
    )
    rpc_update_response_overrides: list[tuple[int, dict[str, object]] | None] = field(
        default_factory=list[tuple[int, dict[str, object]] | None]
    )
    rpc_response_overrides: list[tuple[int, dict[str, object]] | None] = field(
        default_factory=list[tuple[int, dict[str, object]] | None]
    )
    hard_fail: bool = False
    site_authentication_method: object = 'default'


def _apply_human_session_sudo(
    state: FakeSG,
    auth: dict[str, object],
    owner: dict[str, object],
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    sudo_login = auth.get('sudo_as_login')
    if owner.get('type') != 'HumanUser' or not isinstance(sudo_login, str):
        return owner, None
    if state.rpc_human_sudo_mode == 'reject':
        return None, {
            'exception': True,
            'message': f'Cannot sudo as {sudo_login}',
            'error_code': 102,
        }
    if state.rpc_human_sudo_mode == 'ignore':
        return owner, None
    if state.rpc_human_sudo_mode != 'honor':
        raise AssertionError(f'unsupported rpc_human_sudo_mode: {state.rpc_human_sudo_mode!r}')
    if sudo_login not in state.human_logins or sudo_login == state.disabled_login:
        return None, {
            'exception': True,
            'message': f'Cannot sudo as {sudo_login}',
            'error_code': 102,
        }
    return {
        'type': 'HumanUser',
        'id': state.human_logins[sudo_login],
        'name': sudo_login,
    }, None


def _exact_api_user_snapshot_name(spec: dict[str, object]) -> str | None:
    script_name: str | None = None
    filters = spec.get('filters')
    if isinstance(filters, dict):
        conditions = cast('dict[str, object]', filters).get('conditions')
        if isinstance(conditions, list):
            condition_entries = cast('list[object]', conditions)
            if len(condition_entries) == 1 and isinstance(condition_entries[0], dict):
                condition = cast('dict[str, object]', condition_entries[0])
                values = condition.get('values')
                if isinstance(values, list):
                    value_entries = cast('list[object]', values)
                    if len(value_entries) == 1 and isinstance(value_entries[0], str):
                        script_name = value_entries[0]
    if script_name is None:
        return None
    expected = {
        'type': 'ApiUser',
        'return_fields': ['id', 'firstname', 'permission_rule_set'],
        'filters': {
            'logical_operator': 'and',
            'conditions': [
                {'path': 'firstname', 'relation': 'is', 'values': [script_name]},
            ],
        },
        'paging': {'current_page': 1, 'entities_per_page': 2},
        'return_only': 'active',
        'return_paging_info': False,
    }
    return script_name if spec == expected else None


def _human_session_login(state: FakeSG, token: str) -> str | None:
    login = state.web_sessions.get(token)
    if login is None and token.startswith('sess-human-'):
        login = token.removeprefix('sess-human-')
    if login is None and token.startswith('sess-sudo-mint-'):
        login = token.removeprefix('sess-sudo-mint-')
    if login is None and token.startswith('sess-sudo-renewed-'):
        login = token.removeprefix('sess-sudo-renewed-')
    return login if login in state.human_logins else None


def _human_users_response(state: FakeSG, path: str) -> tuple[int, dict[str, object]]:
    emails = parse_qs(urlsplit(path).query).get('filter[email]')
    if emails is None:
        return 200, {'data': [{'id': 5, 'attributes': {'login': 'tuser'}}]}
    if state.fail_user_lookup:
        return 500, {'errors': [{'title': 'internal error'}]}
    if state.duplicate_email and emails[0] == state.duplicate_email:
        return 200, {
            'data': [
                {'id': 7, 'type': 'human_users', 'attributes': {'login': 'dupe.one'}},
                {'id': 8, 'type': 'human_users', 'attributes': {'login': 'dupe.two'}},
            ]
        }
    login = state.known_emails.get(emails[0])
    if login is None:
        return 200, {'data': []}
    return 200, {'data': [{'id': 7, 'type': 'human_users', 'attributes': {'login': login}}]}


def _entity_get_response(
    state: FakeSG, path: str, bearer: str
) -> tuple[int, dict[str, object] | str]:
    if state.fail_entities_status:
        body: dict[str, object] | str = {'errors': [{'title': 'server error'}]}
        if state.entities_non_json:
            body = '<html>request rejected</html>'
        return state.fail_entities_status, body
    if bearer in state.dead_bearers:
        return 401, {'errors': [{'title': 'Authentication failed'}]}
    if path.startswith('/api/v1.1/entity/projects'):
        is_sudo = bearer.startswith('rest-sudo')
        count = state.sudo_project_count if is_sudo else state.plain_project_count
        data = [{'id': i + 1, 'attributes': {'name': f'p{i + 1}'}} for i in range(count)]
        return 200, {'data': data}
    if path.startswith('/api/v1.1/entity/human_users'):
        return _human_users_response(state, path)
    return 404, {'errors': [{'title': 'not found'}]}


def _permission_matrix_response(
    state: FakeSG,
    owner: dict[str, object],
    spec: dict[str, object],
) -> tuple[int, dict[str, object]] | None:
    filters = cast('dict[str, object]', spec.get('filters', {}))
    entity_type = spec.get('type')
    owner_type = owner.get('type')
    owner_id = owner.get('id')
    if not (
        spec.get('return_paging_info') is True
        and filters.get('logical_operator') == 'and'
        and filters.get('conditions') == []
        and isinstance(entity_type, str)
        and isinstance(owner_type, str)
        and type(owner_id) is int
    ):
        return None
    key = (owner_type, owner_id, entity_type)
    configured_response = state.rpc_permission_matrix_responses.get(key)
    if configured_response is not None:
        return 200, dict(configured_response)
    configured_count = state.rpc_permission_matrix_counts.get(key)
    if configured_count is not None:
        return 200, {'results': {'paging_info': {'entity_count': configured_count}}}
    return None


def _record_rpc_session_activity(state: FakeSG, token: str) -> None:
    if state.rpc_idle_window_seconds is None or token not in state.rpc_session_last_activity:
        return
    state.rpc_session_last_activity[token] = state.rpc_now


def _register_rpc_session(state: FakeSG, token: object) -> None:
    if state.rpc_idle_window_seconds is None or not isinstance(token, str) or not token:
        return
    state.rpc_session_last_activity[token] = state.rpc_now


def _rest_response(state: FakeSG, raw: str) -> tuple[int, dict[str, object] | str]:
    if state.fail_rest:
        body: dict[str, object] | str = {'errors': [{'title': state.rest_failure_title}]}
        if state.rest_non_json:
            body = '<html>request rejected</html>'
        return state.rest_failure_status, body
    if state.rest_credentials:
        form = parse_qs(raw)
        client_id = form.get('client_id', [''])[0]
        client_secret = form.get('client_secret', [''])[0]
        if state.rest_credentials.get(client_id) != client_secret:
            return 401, {'errors': [{'title': 'Authentication failed'}]}
    scope = parse_qs(raw).get('scope', [''])[0]
    if scope:
        state.rest_scopes.append(scope)
        sudo_login = scope.partition(':')[2]
        if state.bogus_sudo_failure_status and 'no_such_user' in sudo_login:
            return state.bogus_sudo_failure_status, {'errors': [{'title': 'server error'}]}
        if 'no_such_user' in sudo_login:
            return 400, {'errors': [{'title': f'Cannot sudo as {sudo_login}'}]}
        if state.disabled_login and sudo_login == state.disabled_login:
            return 401, {
                'errors': [{'title': f"Cannot 'sudo' - inactive user account: '{sudo_login}'"}]
            }
    token = f'rest-{scope}' if scope else state.canned_rest
    return 200, {
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': state.rest_expires_in,
        'refresh_token': 'refresh-should-never-leak',
    }


def _rpc_api_user_snapshot_response(
    state: FakeSG,
    spec: dict[str, object],
) -> tuple[int, dict[str, object]] | None:
    script_name = _exact_api_user_snapshot_name(spec)
    if script_name is None:
        return None
    configured = state.rpc_api_users.get(script_name)
    entities: list[dict[str, object]] = []
    if configured is not None:
        api_user_id, role_id, role_name = configured
        entities.append(
            {
                'type': 'ApiUser',
                'id': api_user_id,
                'firstname': script_name,
                'permission_rule_set': {
                    'type': 'PermissionRuleSet',
                    'id': role_id,
                    'name': role_name,
                },
            }
        )
    return 200, {'results': {'entities': entities}}


def _rpc_configured_script_response(
    state: FakeSG,
    auth: dict[str, object],
) -> dict[str, object] | None:
    script_name = auth.get('script_name')
    if not isinstance(script_name, str) or script_name not in state.rpc_api_users:
        return None
    api_user_id, _, _ = state.rpc_api_users[script_name]
    token = f'sess-script-{script_name}'
    state.rpc_script_sessions[token] = {
        'type': 'ApiUser',
        'id': api_user_id,
        'name': script_name,
    }
    _register_rpc_session(state, token)
    return {
        'session_id': token,
        'user_type': 'ApiUser',
        'user_id': api_user_id,
    }


def _rpc_human_login_response(state: FakeSG, auth: dict[str, object]) -> dict[str, object]:
    login = str(auth['user_login'])
    password_ok = auth.get('user_password') == state.human_password
    if password_ok and login in state.human_logins and login != state.disabled_login:
        return {
            'session_id': f'sess-human-{login}',
            'user_type': 'HumanUser',
            'user_id': state.human_logins[login],
        }
    return {'exception': True, 'message': 'Cannot authenticate', 'error_code': 102}


def _rpc_read_owner_response(
    state: FakeSG,
    auth: dict[str, object],
    spec: dict[str, object],
    owner: dict[str, object],
) -> tuple[int, dict[str, object]]:
    matrix_response = _permission_matrix_response(state, owner, spec)
    if matrix_response is not None:
        return matrix_response
    api_user_response = _rpc_api_user_snapshot_response(state, spec)
    if api_user_response is not None:
        return api_user_response
    if spec.get('type') == 'Project':
        updated_owner, error = _apply_human_session_sudo(state, auth, owner)
        if error is not None:
            return 200, error
        assert updated_owner is not None
        login = updated_owner.get('name')
        count = (
            state.human_project_counts.get(str(login), state.sudo_project_count)
            if updated_owner.get('type') == 'HumanUser'
            else state.plain_project_count
        )
        entities = [{'type': 'Project', 'id': 1}] if count else []
        return 200, {
            'results': {
                'entities': entities,
                'paging_info': {'entity_count': count},
            }
        }
    filters = cast('dict[str, object]', spec.get('filters', {}))
    conditions = cast('list[dict[str, object]]', filters.get('conditions', []))
    values = cast('list[object]', conditions[0].get('values', [])) if conditions else []
    login = str(values[0]) if values else ''
    entities: object = state.rpc_read_entities_override
    if entities is None:
        found: list[dict[str, object]] = []
        if login in state.human_logins:
            status = 'dis' if login == state.disabled_login else 'act'
            entity: dict[str, object] = {
                'type': 'HumanUser',
                'id': state.human_logins[login],
                'login': login,
                'sg_status_list': status,
            }
            role = state.human_permission_roles.get(login)
            if role is not None:
                role_id, role_name = role
                entity['permission_rule_set'] = {
                    'type': 'PermissionRuleSet',
                    'id': role_id,
                    'name': role_name,
                }
            found.append(entity)
        entities = found
    entity_count = len(cast('list[object]', entities)) if isinstance(entities, list) else 0
    return 200, {'results': {'entities': entities, 'paging_info': {'entity_count': entity_count}}}


def _rpc_session_is_expired(state: FakeSG, token: str) -> bool:
    if state.rpc_idle_window_seconds is None:
        return False
    last_activity = state.rpc_session_last_activity.get(token)
    if last_activity is None:
        return False
    return state.rpc_now - last_activity >= state.rpc_idle_window_seconds


def _rpc_sudo_mint_response(state: FakeSG, auth: dict[str, object]) -> dict[str, object]:
    login = auth.get('sudo_as_login')
    script_name = auth.get('script_name')
    if isinstance(script_name, str) and isinstance(login, str):
        failure = state.rpc_sudo_mint_failures.get((script_name, login))
        if failure is not None:
            return dict(failure)
        if state.rpc_api_users and script_name not in state.rpc_sudo_enabled_scripts:
            return {
                'exception': True,
                'message': 'Script may not act as another user',
                'error_code': 102,
            }
    if (
        not isinstance(login, str)
        or login not in state.human_logins
        or login == state.disabled_login
    ):
        return {'exception': True, 'message': 'Cannot sudo', 'error_code': 102}
    identity = state.rpc_sudo_mint_identity_override
    if identity is None:
        identity = {'user_type': 'HumanUser', 'user_id': state.human_logins[login]}
    if state.rpc_unique_human_sessions:
        state.human_session_serial += 1
        session_id = f'sess-sudo-mint-{login}-{state.human_session_serial}'
    else:
        session_id = f'sess-sudo-mint-{login}'
    state.issued_human_sessions.add(session_id)
    state.web_sessions[session_id] = login
    _register_rpc_session(state, session_id)
    return {'session_id': session_id, **identity}


def _session_owner(state: FakeSG, token: str) -> dict[str, object] | None:
    script_owner = state.rpc_script_sessions.get(token)
    if script_owner is not None:
        return dict(script_owner)
    if token == state.canned_session and not state.session_revoked:
        return dict(_API_USER_ENTITY)
    login = _human_session_login(state, token)
    disabled_session_works = (
        state.rpc_disabled_human_sessions_work
        and bool(state.disabled_login)
        and login == state.disabled_login
    )
    if token in state.disabled_human_sessions and not disabled_session_works:
        return None
    if login is not None and (
        login != state.disabled_login or state.rpc_disabled_human_sessions_work
    ):
        return {'type': 'HumanUser', 'id': state.human_logins[login], 'name': login}
    return None


def _rpc_create_response(
    state: FakeSG, params: list[dict[str, object]]
) -> tuple[int, dict[str, object]]:
    if state.rpc_create_response_overrides:
        override = state.rpc_create_response_overrides.pop(0)
        if override is not None:
            return override
    auth = params[0]
    owner = _session_owner(state, str(auth.get('session_token', '')))
    if owner is None:
        return 200, {'exception': True, 'message': 'Session expired', 'error_code': 102}
    created_by = owner
    sudo_login = auth.get('sudo_as_login')
    if isinstance(sudo_login, str) and not state.sudo_ignored:
        if sudo_login not in state.human_logins or sudo_login == state.disabled_login:
            message = f'Cannot sudo as {sudo_login}'
            return 200, {'exception': True, 'message': message, 'error_code': 102}
        created_by = {
            'type': 'HumanUser',
            'id': state.human_logins[sudo_login],
            'name': sudo_login,
        }
    return 200, {'results': {'type': 'Note', 'id': 901, 'created_by': created_by}}


def _rpc_delete_response(
    state: FakeSG, params: list[dict[str, object]]
) -> tuple[int, dict[str, object]]:
    auth = params[0]
    owner = _session_owner(state, str(auth.get('session_token', '')))
    if owner is None:
        return 200, {'exception': True, 'message': 'Session expired', 'error_code': 102}
    if state.rpc_human_delete_forbidden and owner.get('type') == 'HumanUser':
        return 200, {
            'exception': True,
            'message': 'Entity of type Note can not be deleted by this user.',
            'error_code': 4,
        }
    return 200, {'results': True}


def _rpc_read_response(
    state: FakeSG, params: list[dict[str, object]]
) -> tuple[int, dict[str, object]]:
    auth = params[0]
    token = str(auth.get('session_token', ''))
    if _rpc_session_is_expired(state, token):
        return 200, {'exception': True, 'message': 'Session expired', 'error_code': 102}
    spec = params[1]
    login = _human_session_login(state, token)
    if (
        spec.get('type') == 'Project'
        and login == state.disabled_login
        and state.rpc_disabled_human_read_error_code is not None
    ):
        return 200, {
            'exception': True,
            'message': 'Controlled disabled HumanUser read fault',
            'error_code': state.rpc_disabled_human_read_error_code,
        }
    owner = _session_owner(state, token)
    if owner is None:
        return 200, {'exception': True, 'message': 'Session expired', 'error_code': 102}
    _record_rpc_session_activity(state, token)
    return _rpc_read_owner_response(state, auth, spec, owner)


def _rpc_update_response(
    state: FakeSG, params: list[dict[str, object]]
) -> tuple[int, dict[str, object]]:
    if state.rpc_update_response_overrides:
        override = state.rpc_update_response_overrides.pop(0)
        if override is not None:
            return override
    auth = params[0]
    owner = _session_owner(state, str(auth.get('session_token', '')))
    if owner is None:
        return 200, {'exception': True, 'message': 'Session expired', 'error_code': 102}
    payload = params[1]
    assert payload.get('type') == 'HumanUser'
    human_id = payload.get('id')
    assert type(human_id) is int
    login = next(
        (
            known_login
            for known_login, known_id in state.human_logins.items()
            if known_id == human_id
        ),
        None,
    )
    assert login is not None
    fields = payload.get('fields')
    assert isinstance(fields, list)
    typed_fields = cast('list[object]', fields)
    assert len(typed_fields) == 1
    field_object = typed_fields[0]
    assert isinstance(field_object, dict)
    field = cast('dict[str, object]', field_object)
    assert field.get('field_name') == 'sg_status_list'
    status = field.get('value')
    assert isinstance(status, str)
    if status == 'dis':
        state.disabled_login = login
        state.disabled_human_sessions.update(state.issued_human_sessions)
    elif status == 'act' and state.disabled_login == login:
        state.disabled_login = ''
        if not state.rpc_known_human_sessions_stay_dead:
            state.disabled_human_sessions.clear()
    return 200, {
        'results': {
            'type': 'HumanUser',
            'id': human_id,
            'sg_status_list': status,
        }
    }


def _rpc_method_response(
    state: FakeSG,
    method: object,
    params: list[dict[str, object]],
) -> tuple[int, dict[str, object]] | None:
    if method == 'info':
        body: dict[str, object] = {}
        if state.site_authentication_method is not None:
            body['user_authentication_method'] = state.site_authentication_method
        return 200, body
    if method == 'create':
        return _rpc_create_response(state, params)
    if method == 'delete':
        return _rpc_delete_response(state, params)
    if method == 'read':
        return _rpc_read_response(state, params)
    if method == 'update':
        return _rpc_update_response(state, params)
    return None


def _session_payload(state: FakeSG) -> dict[str, object]:
    identity = (
        {'user_type': 'ApiUser', 'user_id': 2442}
        if state.rpc_mint_identity_override is None
        else state.rpc_mint_identity_override
    )
    if state.rpc_missing_session_id:
        return dict(identity)
    session_id = (
        state.canned_session
        if state.rpc_session_id_override is None
        else state.rpc_session_id_override
    )
    _register_rpc_session(state, session_id)
    if state.nested_results:
        return {'results': {'session_id': session_id}}
    return {'session_id': session_id, **identity}


def _rpc_session_token_response(state: FakeSG, auth: dict[str, object]) -> dict[str, object]:
    token = str(auth.get('session_token', ''))
    owner = _session_owner(state, token)
    if owner is None:
        return {'exception': True, 'message': 'Session expired', 'error_code': 102}
    owner, error = _apply_human_session_sudo(state, auth, owner)
    if error is not None:
        return error
    assert owner is not None
    if owner.get('type') == 'HumanUser':
        login = str(owner['name'])
        session_id = state.rpc_human_renewed_session
        if not session_id:
            session_id = (
                f'sess-sudo-renewed-{login}' if token.startswith('sess-sudo-mint-') else token
            )
        state.issued_human_sessions.add(session_id)
        state.web_sessions[session_id] = login
        return {
            'session_id': session_id,
            'user_type': 'HumanUser',
            'user_id': owner['id'],
        }
    return _session_payload(state)


def _rpc_auth_response(state: FakeSG, auth: dict[str, object]) -> dict[str, object]:
    if 'user_login' in auth:
        return _rpc_human_login_response(state, auth)
    if 'session_token' in auth:
        return _rpc_session_token_response(state, auth)
    if 'sudo_as_login' in auth:
        return _rpc_sudo_mint_response(state, auth)
    configured_body = _rpc_configured_script_response(state, auth)
    if configured_body is not None:
        return configured_body
    if state.fail_rpc:
        return {'exception': True, 'message': 'Cannot authenticate', 'error_code': 102}
    return _session_payload(state)


def _rpc_response(state: FakeSG, raw: str) -> tuple[int, dict[str, object]]:
    if state.rpc_response_overrides:
        override = state.rpc_response_overrides.pop(0)
        if override is not None:
            return override
    if state.weird_json:
        status = 403 if state.rpc_status_override is None else state.rpc_status_override
        return status, {'message': 'blocked-by-policy'}
    status = 200 if state.rpc_status_override is None else state.rpc_status_override
    if state.rpc_fault:
        error_code = (
            100 if state.rpc_error_code_override is None else state.rpc_error_code_override
        )
        return status, {
            'exception': True,
            'message': 'unexpected server fault',
            'error_code': error_code,
        }
    payload = cast('dict[str, object]', json.loads(raw))
    method = payload.get('method_name')
    params = cast('list[dict[str, object]]', payload.get('params') or [{}])
    method_response = _rpc_method_response(state, method, params)
    if method_response is not None:
        method_status, method_body = method_response
        return status if state.rpc_status_override is not None else method_status, method_body
    auth = params[0]
    body = _rpc_auth_response(state, auth)
    if state.rpc_results_as_list and 'results' in body:
        body['results'] = [body['results']]
    return status, body


def _make_handler(state: FakeSG) -> type[BaseHTTPRequestHandler]:

    class Handler(BaseHTTPRequestHandler):
        def log_request(self, code: int | str = '-', size: int | str = '-') -> None:
            del code, size

        def _send(self, status: int, body: dict[str, object] | str) -> None:
            payload = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            self.send_response(status)
            content_type = 'text/html' if isinstance(body, str) else 'application/json'
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            if state.hard_fail:
                self.connection.close()
                return
            length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(length).decode()
            state.requests.append({'path': self.path, 'body': raw})
            if self.path == '/api3/json':
                self._send(*_rpc_response(state, raw))
                return
            if self.path == '/api/v1.1/auth/access_token':
                self._send(*_rest_response(state, raw))
                return
            self._send(404, {'errors': [{'title': 'not found'}]})

        def do_GET(self) -> None:
            if state.hard_fail:
                self.connection.close()
                return
            bearer = self.headers.get('Authorization', '').removeprefix('Bearer ')
            state.requests.append({'path': self.path, 'body': '', 'bearer': bearer})
            self._send(*_entity_get_response(state, self.path, bearer))

    return Handler


@pytest.fixture
def fake_sg() -> Iterator[FakeSG]:
    state = FakeSG()
    server = ThreadingHTTPServer(('127.0.0.1', 0), _make_handler(state))
    state.url = f'http://127.0.0.1:{server.server_address[1]}'
    thread = threading.Thread(
        target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
    )
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


@pytest.fixture
def broker_url(fake_sg: FakeSG, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv('SGTB_KEY_READ_ALL', 'masterkey')
    fake_sg.rest_credentials = {'broker_read_all': 'masterkey'}
    cfg_path = tmp_path / 'broker.yml'
    cfg_path.write_text(f"""
site_url: {fake_sg.url}
server:
  bind: 127.0.0.1
  port: 0
scopes:
  read_all:
    script_name: broker_read_all
    script_key_env: SGTB_KEY_READ_ALL
clients:
  farm:
    secret_hash: "{BROKER_HASH}"
    scopes: [read_all]
""")
    config = load_config(cfg_path)
    service = BrokerService(
        config=config,
        minter=SGMinter(config.site_url),
        cache=TTLCache(),
        audit=AuditLogger(),
    )
    server = create_server(config, service)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
    )
    thread.start()
    yield f'http://127.0.0.1:{server.server_address[1]}'
    server.shutdown()
    server.server_close()


@pytest.fixture
def no_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        requests.Session, 'request', Mock(side_effect=AssertionError('unexpected HTTP request'))
    )


@pytest.fixture
def offline_sg(no_requests: None) -> FakeSG:
    del no_requests
    return FakeSG(url='http://127.0.0.1:1')
