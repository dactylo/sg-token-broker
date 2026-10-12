"""Resolve caller emails to SG logins via the REST `human_users` endpoint."""

import re
from http import HTTPStatus
from typing import Protocol, cast

import requests

from sg_token_broker._cache import TTLCache
from sg_token_broker._sg import MintedToken, SGError
from sg_token_broker._urlpolicy import require_https_or_loopback

_HUMAN_USERS_PATH = '/api/v1.1/entity/human_users'
_LOOKUP_CACHE_TTL_SECONDS = 300.0
_REQUEST_TIMEOUT_SECONDS = 10.0
_SAFE_EMAIL_RE = re.compile(r"^[a-z0-9._%+'-]+@[a-z0-9.-]+$")


class UnknownUserError(Exception):
    """No single SG HumanUser matches the email."""


class UserLookupError(Exception):
    """The SG user lookup could not be completed."""


class _PlainMinter(Protocol):
    """Anything that can mint plain SG REST tokens from script credentials."""

    def mint_rest_token(self, script_name: str, script_key: str) -> MintedToken:
        """Mint an SG REST access token.

        Args:
            script_name: ApiUser script name.
            script_key: ApiUser application key.

        Returns:
            The minted token.

        Raises:
            SGError: If the upstream token request cannot be completed.
        """
        ...


class UserDirectory:
    """Resolve studio emails to SG logins, caching results for about 5 minutes."""

    def __init__(
        self,
        site_url: str,
        minter: _PlainMinter,
        script_name: str,
        script_key: str,
    ) -> None:
        """Configure SG lookup credentials and the email-to-login cache.

        Args:
            site_url: Base URL of the SG site.
            minter: SG minter for plain lookup tokens.
            script_name: Service ApiUser script name.
            script_key: Service ApiUser application key.

        Raises:
            UserLookupError: If `site_url` is malformed, unsupported, or
                insecure.
        """
        try:
            self._site_url = require_https_or_loopback(site_url, 'SG site URL').rstrip('/')
        except ValueError as exc:
            raise UserLookupError(str(exc)) from exc
        self._minter = minter
        self._script_name = script_name
        self._script_key = script_key
        self._cache = TTLCache[str]()
        self._session = requests.Session()

    def _lookup(self, email: str) -> str:
        """Return the uncached SG login matching `email`."""
        try:
            bearer = self._minter.mint_rest_token(self._script_name, self._script_key).token
        except SGError as exc:
            raise UserLookupError('could not mint the lookup token') from exc
        try:
            response = self._session.get(
                f'{self._site_url}{_HUMAN_USERS_PATH}',
                params={'filter[email]': email, 'fields': 'login'},
                headers={'Authorization': f'Bearer {bearer}', 'Accept': 'application/json'},
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            raise UserLookupError(f'SG user lookup failed: {exc.__class__.__name__}') from exc
        if response.status_code != HTTPStatus.OK:
            raise UserLookupError(f'SG user lookup returned HTTP {response.status_code}')
        try:
            body: object = response.json()
        except ValueError as exc:
            raise UserLookupError('SG user lookup response was not JSON') from exc
        return _extract_login(body)

    def resolve_login(self, email: str) -> str:
        """Return the SG login for the (case-insensitive) email.

        Only successful lookups are cached; an unknown identity costs an SG
        lookup per request.
        Accepted under the current threat model.

        Args:
            email: The caller's verified email address.

        Returns:
            The matching HumanUser login.

        Raises:
            UnknownUserError: If no single SG HumanUser matches or the email
                contains characters outside the supported set.
            UserLookupError: If SG cannot be queried.
        """
        key = email.lower()
        if _SAFE_EMAIL_RE.fullmatch(key) is None:
            raise UnknownUserError('email contains unsupported characters')
        login, _ = self._cache.get_or_create(
            key, _LOOKUP_CACHE_TTL_SECONDS, lambda: self._lookup(key)
        )
        return login


def _extract_login(body: object) -> str:
    """Pull the single matching login out of a human_users response."""
    if not isinstance(body, dict):
        raise UserLookupError('SG user lookup response was not a JSON object')
    data = cast('dict[str, object]', body).get('data')
    if not isinstance(data, list):
        raise UserLookupError('SG user lookup response had no data list')
    entries = cast('list[object]', data)
    if len(entries) != 1:
        raise UnknownUserError(f'{len(entries)} SG users match the email')
    entry = entries[0]
    if not isinstance(entry, dict):
        raise UserLookupError('SG user lookup entry was not an object')
    attributes = cast('dict[str, object]', entry).get('attributes')
    if not isinstance(attributes, dict):
        raise UserLookupError('SG user lookup entry had no attributes')
    login = cast('dict[str, object]', attributes).get('login')
    if not isinstance(login, str) or not login:
        raise UserLookupError('SG user lookup entry had no login')
    return login
