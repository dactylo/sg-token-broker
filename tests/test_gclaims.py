from collections.abc import Mapping

import pytest
import requests

from sg_token_broker._gclaims import (
    ClaimsError,
    ClaimsValidator,
    OidcClaimsValidator,
    VerifiedClaims,
    Verifier,
)

AUDIENCE = 'client-id-123.apps.googleusercontent.com'
DOMAIN = 'studio.example'
EMAIL = 'jane.exec@studio.example'


class TestOidcClaimsValidator:
    def test_accepts_array_audience_with_azp(self) -> None:
        payload = _payload(aud=['client-1', 'other'], azp='client-1')
        assert _validator(payload=payload).validate('Bearer t').audience == 'client-1'

    def test_accepts_string_audience(self) -> None:
        claims = _validator().validate('Bearer t')
        assert claims == VerifiedClaims(email='jane@studio.example', audience='client-1')

    def test_assume_email_verified_override(self) -> None:
        payload = _payload()
        del payload['email_verified']
        claims = _validator(payload=payload, assume_email_verified=True).validate('Bearer t')
        assert claims.email == 'jane@studio.example'

    def test_assume_email_verified_rejects_false(self) -> None:
        with pytest.raises(ClaimsError, match='verified'):
            _validator(
                payload=_payload(email_verified=False), assume_email_verified=True
            ).validate('Bearer t')

    def test_assume_email_verified_rejects_malformed_value(self) -> None:
        with pytest.raises(ClaimsError, match='verified'):
            _validator(
                payload=_payload(email_verified='true'), assume_email_verified=True
            ).validate('Bearer t')

    def test_assume_email_verified_rejects_null(self) -> None:
        with pytest.raises(ClaimsError, match='verified'):
            _validator(payload=_payload(email_verified=None), assume_email_verified=True).validate(
                'Bearer t'
            )

    def test_configurable_email_claim(self) -> None:
        payload = _payload(upn='jane@studio.example')
        del payload['email']
        claims = _validator(payload=payload, email_claim='upn').validate('Bearer t')
        assert claims.email == 'jane@studio.example'

    def test_domain_is_exact_equality(self) -> None:
        payload = _payload(email='jane@evilstudio.example')
        with pytest.raises(ClaimsError, match='domain'):
            _validator(payload=payload).validate('Bearer t')

    def test_rejects_array_audience_without_azp(self) -> None:
        payload = _payload(aud=['client-1', 'other'])
        with pytest.raises(ClaimsError, match='azp'):
            _validator(payload=payload).validate('Bearer t')

    def test_rejects_azp_absent_from_the_token_audiences(self) -> None:
        # Both client-1 and client-2 are configured; the token's aud
        # satisfies client-1 but its azp names client-2. One client must
        # satisfy both checks.
        payload = _payload(aud=['client-1', 'other'], azp='client-2')
        with pytest.raises(ClaimsError, match='azp'):
            _validator(payload=payload).validate('Bearer t')

    def test_rejects_disjoint_audience(self) -> None:
        with pytest.raises(ClaimsError, match='audience'):
            _validator(payload=_payload(aud='stranger')).validate('Bearer t')

    def test_requires_email_verified_by_default(self) -> None:
        with pytest.raises(ClaimsError, match='verified'):
            _validator(payload=_payload(email_verified=False)).validate('Bearer t')

    def test_verifier_transport_failure_propagates(self) -> None:
        failure = requests.RequestException('provider unavailable')

        def verify(_presented: str) -> Mapping[str, object]:
            raise failure

        validator = OidcClaimsValidator(verify, ['client-1'], 'studio.example')
        with pytest.raises(requests.RequestException) as excinfo:
            validator.validate('Bearer t')
        assert excinfo.value is failure


class TestValidate:
    def test_accepts_valid_token(self) -> None:
        claims = _make_validator(_make_payload()).validate('Bearer goodvalue')
        assert claims.email == EMAIL
        assert claims.audience == AUDIENCE

    @pytest.mark.parametrize('header', ['Bearer', 'Bearer   '])
    def test_bearer_without_credential_is_rejected(self, header: str) -> None:
        with pytest.raises(ClaimsError, match='Authorization'):
            _make_validator(_make_payload()).validate(header)

    def test_email_is_lowercased(self) -> None:
        payload = _make_payload(email='Jane.Exec@Studio.Example')
        assert _make_validator(payload).validate('Bearer goodvalue').email == EMAIL

    def test_empty_header_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='Authorization'):
            _make_validator(_make_payload()).validate('')

    def test_hd_case_is_normalized(self) -> None:
        payload = _make_payload(hd='Studio.Example')
        assert _make_validator(payload).validate('Bearer goodvalue').email == EMAIL

    def test_list_audience_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='audience'):
            _make_validator(_make_payload(aud=[AUDIENCE])).validate('Bearer goodvalue')

    @pytest.mark.parametrize(
        'email',
        [
            'user@sub.studio.example',
            'user@evilstudio.example',
            'user@studio.example.evil',
        ],
    )
    def test_lookalike_domain_is_rejected(self, email: str) -> None:
        with pytest.raises(ClaimsError, match='domain'):
            _make_validator(_make_payload(email=email)).validate('Bearer goodvalue')

    def test_missing_audience_is_rejected(self) -> None:
        payload = _make_payload()
        del payload['aud']
        with pytest.raises(ClaimsError, match='audience'):
            _make_validator(payload).validate('Bearer goodvalue')

    def test_missing_email_is_rejected(self) -> None:
        payload = _make_payload()
        del payload['email']
        with pytest.raises(ClaimsError, match='email'):
            _make_validator(payload).validate('Bearer goodvalue')

    def test_missing_hd_is_rejected(self) -> None:
        payload = _make_payload()
        del payload['hd']
        with pytest.raises(ClaimsError, match='hd'):
            _make_validator(payload).validate('Bearer goodvalue')

    def test_multiple_at_signs_use_final_domain(self) -> None:
        payload = _make_payload(email='evil@studio.example@attacker.example')
        with pytest.raises(ClaimsError, match='domain'):
            _make_validator(payload).validate('Bearer goodvalue')

    def test_non_bearer_scheme_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='Authorization'):
            _make_validator(_make_payload()).validate('Basic abc')

    def test_non_string_hd_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='hd'):
            _make_validator(_make_payload(hd=True)).validate('Bearer goodvalue')

    def test_none_email_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='email'):
            _make_validator(_make_payload(email=None)).validate('Bearer goodvalue')

    def test_quoted_local_part_at_allowed_domain_is_accepted(self) -> None:
        payload = _make_payload(email='"Evil@Attacker.Example"@Studio.Example')
        claims = _make_validator(payload).validate('Bearer goodvalue')
        assert claims.email == '"evil@attacker.example"@studio.example'

    def test_string_email_verified_is_rejected(self) -> None:
        payload = _make_payload(email_verified='true')
        with pytest.raises(ClaimsError, match='verified'):
            _make_validator(payload).validate('Bearer goodvalue')

    def test_unknown_audience_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='audience'):
            _make_validator(_make_payload(aud='evil-aud')).validate('Bearer goodvalue')

    def test_unverified_email_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='verified'):
            _make_validator(_make_payload(email_verified=False)).validate('Bearer goodvalue')

    def test_verifier_failure_is_rejected(self) -> None:

        def verify(presented: str) -> Mapping[str, object]:
            raise ValueError(f'bad signature on {presented}')

        with pytest.raises(ClaimsError, match='verification failed'):
            ClaimsValidator(verify, [AUDIENCE], DOMAIN).validate('Bearer forged')

    def test_wrong_domain_is_rejected(self) -> None:
        payload = _make_payload(email='intruder@evil.example')
        with pytest.raises(ClaimsError, match='domain'):
            _make_validator(payload).validate('Bearer goodvalue')

    def test_wrong_hd_is_rejected(self) -> None:
        with pytest.raises(ClaimsError, match='hd'):
            _make_validator(_make_payload(hd='evil.example')).validate('Bearer goodvalue')


def _constant_verifier(payload: Mapping[str, object]) -> Verifier:

    def verify(presented: str) -> Mapping[str, object]:
        del presented
        return payload

    return verify


def _make_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        'aud': AUDIENCE,
        'email': EMAIL,
        'email_verified': True,
        'hd': DOMAIN,
    }
    payload.update(overrides)
    return payload


def _make_validator(payload: Mapping[str, object]) -> ClaimsValidator:
    return ClaimsValidator(_constant_verifier(payload), [AUDIENCE, 'second-aud'], DOMAIN)


def _payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        'aud': 'client-1',
        'email': 'jane@studio.example',
        'email_verified': True,
    }
    return base | overrides


def _validator(
    *,
    payload: Mapping[str, object] | None = None,
    email_claim: str = 'email',
    assume_email_verified: bool = False,
) -> OidcClaimsValidator:
    if payload is None:
        payload = _payload()
    return OidcClaimsValidator(
        lambda _: payload,
        ['client-1', 'client-2'],
        'studio.example',
        email_claim=email_claim,
        assume_email_verified=assume_email_verified,
    )
