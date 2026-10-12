"""Validate verified Google and OIDC identity claims."""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TypeAlias, cast

Verifier: TypeAlias = Callable[[str], Mapping[str, object]]


class ClaimsError(Exception):
    """The presented identity token is missing, invalid, or not allowed."""


@dataclass(frozen=True)
class VerifiedClaims:
    """Contain claims extracted from a verified identity token.

    Attributes:
        email: Verified, normalized email address.
        audience: Accepted audience matched by the validator.
    """

    email: str
    audience: str


class ClaimsValidator:
    """Validate Authorization headers carrying Google ID tokens."""

    def __init__(self, verifier: Verifier, audiences: Iterable[str], allowed_domain: str) -> None:
        """Configure Google claim verification and audience policy.

        Args:
            verifier: Checks the token signature and expiry and returns its
                claims, raising `ValueError` for an invalid token.
            audiences: Accepted Cloud Run custom audience values, such as the
                calling scripts' OAuth client IDs.
            allowed_domain: Email domain without `@` that callers and the
                token's `hd` claim must match.
        """
        self._verifier = verifier
        self._audiences = frozenset(audiences)
        self._allowed_domain = allowed_domain.lower()

    def validate(self, authorization: str) -> VerifiedClaims:
        """Verify the Authorization header's ID token and validate its claims.

        Args:
            authorization: Raw Authorization header value (`Bearer <token>`).

        Returns:
            The verified email (lowercased) and audience.

        Raises:
            ClaimsError: If the header is malformed, the signature/expiry check
                fails, or any claim check fails.
        """
        presented = _extract_bearer(authorization)
        try:
            payload = self._verifier(presented)
        except ValueError as exc:
            raise ClaimsError('identity token verification failed') from exc
        audience = payload.get('aud')
        if not isinstance(audience, str) or audience not in self._audiences:
            raise ClaimsError('audience not accepted')
        if payload.get('email_verified') is not True:
            raise ClaimsError('email is not verified')
        email = payload.get('email')
        if not isinstance(email, str) or '@' not in email:
            raise ClaimsError('email claim missing')
        email = email.lower()
        if email.rpartition('@')[2] != self._allowed_domain:
            raise ClaimsError('email domain not allowed')
        hosted_domain = payload.get('hd')
        if not isinstance(hosted_domain, str) or hosted_domain.lower() != self._allowed_domain:
            raise ClaimsError('hd claim missing or not allowed')
        return VerifiedClaims(email=email, audience=audience)


class OidcClaimsValidator:
    """Validate Authorization headers carrying generic OIDC ID tokens."""

    def __init__(
        self,
        verifier: Verifier,
        audiences: Iterable[str],
        allowed_domain: str,
        *,
        email_claim: str = 'email',
        assume_email_verified: bool = False,
    ) -> None:
        """Configure OIDC claim verification and audience policy.

        Args:
            verifier: Checks the token signature, issuer, and expiry and
                returns its claims, raising `ValueError` for an invalid token.
            audiences: Accepted installed-app audience values.
            allowed_domain: Required email domain without `@`, matched exactly
                after case normalization.
            email_claim: Claim carrying the unique, immutable user email
                address.
                Defaults to `email`.
            assume_email_verified: Accept issuer-asserted addresses when the
                `email_verified` claim is absent. Defaults to `False`.
        """
        self._verifier = verifier
        self._audiences = frozenset(audiences)
        self._allowed_domain = allowed_domain.lower()
        self._email_claim = email_claim
        self._assume_email_verified = assume_email_verified

    def _match_audience(self, payload: Mapping[str, object]) -> str:
        """Apply the OIDC aud/azp acceptance rule and return the matched value."""
        aud = payload.get('aud')
        if isinstance(aud, str):
            candidates = {aud}
        elif isinstance(aud, list) and all(
            isinstance(item, str) for item in cast('list[object]', aud)
        ):
            candidates = set(cast('list[str]', aud))
        else:
            raise ClaimsError('aud claim missing or malformed')
        matched = candidates & self._audiences
        if not matched:
            raise ClaimsError('audience not accepted')
        if len(candidates) > 1:
            azp = payload.get('azp')
            # `matched`, not the configured set: one client identity must
            # satisfy both the aud and azp checks, or two configured
            # clients could be mixed across the two claims.
            if not isinstance(azp, str) or azp not in matched:
                raise ClaimsError('azp missing or not accepted for multi-audience token')
            return azp
        return next(iter(matched))

    def validate(self, authorization: str) -> VerifiedClaims:
        """Verify the header's ID token and validate its claims.

        Args:
            authorization: Raw Authorization header value (`Bearer <token>`).

        Returns:
            The verified email (lowercased) and matched audience.

        Raises:
            ClaimsError: If the header is malformed, verification fails, or any
                claim check fails.
        """
        presented = _extract_bearer(authorization)
        try:
            payload = self._verifier(presented)
        except ValueError as exc:
            raise ClaimsError('identity token verification failed') from exc
        audience = self._match_audience(payload)
        email_verified = payload.get('email_verified')
        if email_verified is not True and not (
            self._assume_email_verified and 'email_verified' not in payload
        ):
            raise ClaimsError('email is not verified')
        email = payload.get(self._email_claim)
        if not isinstance(email, str) or '@' not in email:
            raise ClaimsError(f'{self._email_claim} claim missing')
        email = email.lower()
        if email.rpartition('@')[2] != self._allowed_domain:
            raise ClaimsError('email domain not allowed')
        return VerifiedClaims(email=email, audience=audience)


def _extract_bearer(authorization: str) -> str:
    """Return the bearer token from an Authorization header or raise ClaimsError."""
    scheme, _, presented = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not presented.strip():
        raise ClaimsError('missing or malformed Authorization header')
    return presented.strip()
