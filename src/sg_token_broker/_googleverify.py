"""Google ID-token verification through the optional `google` extra."""

import importlib
import json
from collections.abc import Iterator, Mapping
from functools import lru_cache, partial
from http import HTTPStatus
from typing import NamedTuple, cast

import requests

from sg_token_broker._diagnostics import local_send_detail
from sg_token_broker._gclaims import Verifier


class VerifierUnavailableError(Exception):
    """The Google verification dependency group is incomplete."""


class _CertificateError(RuntimeError):
    """Google certificate retrieval or decoding failed before caller verification."""


class _CertificateResponse(NamedTuple):
    """The response fields consumed by google-auth's certificate reader."""

    status: int
    data: bytes


class _CertificateSet(NamedTuple):
    """Filtered documents for Google's verifiers and IDs unusable in every document."""

    documents: dict[str, bytes]
    unusable: frozenset[str]

    def response(self, presented: str) -> _CertificateResponse:
        """Select candidate certificates for an unverified Google token header.

        Args:
            presented: Encoded identity token whose header guides candidate
                selection.

        Returns:
            An HTTP 200 response containing the filtered JWK set when
            available, otherwise the certificates for the header algorithm or
            an empty JSON object.

        Raises:
            ValueError: If the JWT cannot be decoded with a JSON object for
                both header and payload, or its key ID or signing algorithm is
                malformed.
            RuntimeError: If the selected certificate ID has only unusable
                provider material.
        """
        header = importlib.import_module('google.auth.jwt').decode_header(presented)
        kid = header.get('kid')
        if kid is not None and not isinstance(kid, str):
            raise ValueError('invalid signing key ID')
        if kid in self.unusable:
            raise _CertificateError('Google certificate selected by the token is unusable')
        alg = header.get('alg')
        if not isinstance(alg, str) or not alg:
            raise ValueError('invalid signing algorithm')
        # google-auth tries all X.509 entries for a token without a kid, but its
        # algorithm-specific verifier can raise on the first incompatible key type.
        document = self.documents.get('jwks', self.documents.get(alg, b'{}'))
        return _CertificateResponse(HTTPStatus.OK, document)


def _exception_types(module: object, *names: str) -> tuple[type[Exception], ...]:
    """Discover the available exception classes in an optional JWT installation."""
    types: list[type[Exception]] = []
    for name in names:
        value = getattr(module, name, None)
        if isinstance(value, type) and issubclass(value, Exception):
            types.append(value)
    return tuple(types)


def _jwk_format(entry: object) -> str | None:
    """Identify signing keys that the optional JWK verifier can load."""
    key = importlib.import_module('jwt.api_jwk').PyJWK.from_dict(entry)
    return 'jwks' if key.public_key_use in (None, 'sig') else None


def _named_jwks(keys: object) -> Iterator[tuple[str, object]]:
    """Yield JWK entries addressable by key ID."""
    if not isinstance(keys, list):
        raise _CertificateError('Google certificate response must contain a signing key set')
    for entry in cast('list[object]', keys):
        if isinstance(entry, dict):
            kid = cast('dict[str, object]', entry).get('kid')
            if isinstance(kid, str) and kid:
                yield kid, entry


def _pem_algorithm(pem: object) -> str | None:
    """Identify the X.509 verification algorithm that accepts this public key."""
    if not isinstance(pem, str):
        return None
    try:
        serialization = importlib.import_module('cryptography.hazmat.primitives.serialization')
    except ImportError:
        # Older Google installations can use a pure-Python RSA verifier.
        importlib.import_module('google.auth.crypt').RSAVerifier.from_string(pem)
        return 'RS256'
    unsupported = importlib.import_module('cryptography.exceptions').UnsupportedAlgorithm
    try:
        encoded = pem.encode()
        if b'-----BEGIN CERTIFICATE-----' in encoded:
            x509 = importlib.import_module('cryptography.x509')
            key = x509.load_pem_x509_certificate(encoded).public_key()
        else:
            key = serialization.load_pem_public_key(encoded)
    except unsupported:
        return None
    rsa = importlib.import_module('cryptography.hazmat.primitives.asymmetric.rsa')
    ec = importlib.import_module('cryptography.hazmat.primitives.asymmetric.ec')
    if isinstance(key, rsa.RSAPublicKey):
        return 'RS256'
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {'secp256r1': 'ES256', 'secp384r1': 'ES384'}.get(key.curve.name)
    return None


@lru_cache(maxsize=1)
def _certificate_entries(data: bytes, bad_entry: tuple[type[Exception], ...]) -> _CertificateSet:
    """Prepare each usable entry once per changed certificate response."""
    document: object = json.loads(data)
    if not isinstance(document, dict):
        raise _CertificateError('Google certificate response must contain a signing key set')
    certs = cast('dict[str, object]', document)
    jwks = 'keys' in certs
    entries = _named_jwks(certs['keys']) if jwks else certs.items()
    identify = _jwk_format if jwks else _pem_algorithm
    groups: dict[str, dict[str, object]] = {}
    rejected: set[str] = set()
    for kid, entry in entries:
        try:
            kind = identify(entry)
        except bad_entry:
            kind = None
        if kind is None or not kid:
            rejected.add(kid)
        else:
            groups.setdefault(kind, {}).setdefault(kid, entry)
    if not groups:
        raise _CertificateError(
            'Google certificate response contained no usable signing certificates'
        )
    documents: dict[str, bytes] = {}
    for kind, members in groups.items():
        rejected.difference_update(members)
        filtered = {'keys': list(members.values())} if jwks else members
        documents[kind] = json.dumps(filtered).encode()
    return _CertificateSet(documents, frozenset(rejected))


def google_auth_verifier() -> Verifier:
    """Build a Verifier backed by google-auth ID-token verification.

    The returned callable wraps `verify_oauth2_token`: signature (against
    Google's published certs), expiry, and the `iss` claim are all checked.
    The audience stays unchecked here (`audience=None`); `_gclaims` validates
    `aud` against the configured list. google-auth raises ValueError for
    malformed/invalid tokens and GoogleAuthError for issuer failures; the
    latter is re-raised as ValueError to satisfy the `Verifier` contract.
    Failures retrieving usable signing certificates raise an operational error
    with local diagnostic details.

    Returns:
        A `Verifier` suitable for `ClaimsValidator`.

    Raises:
        VerifierUnavailableError: If the Google verification dependencies are
            incomplete.
    """
    try:
        cachecontrol = importlib.import_module('cachecontrol')
        cache = importlib.import_module('cachecontrol.cache')
        exceptions = importlib.import_module('google.auth.exceptions')
        transport = importlib.import_module('google.auth.transport.requests')
        id_token = importlib.import_module('google.oauth2.id_token')
    except ImportError as exc:
        raise VerifierUnavailableError(
            'Google verification dependencies are incomplete; install the [google] extra'
        ) from exc
    # Google can verify its X.509 certificates without the optional PyJWT package.
    try:
        jwt_errors = importlib.import_module('jwt.exceptions')
    except ImportError:
        jwt_errors = None
    rejections = (
        exceptions.GoogleAuthError,
        ValueError,
        *_exception_types(jwt_errors, 'PyJWKClientError', 'InvalidTokenError'),
    )
    outages = (
        exceptions.TransportError,
        *_exception_types(jwt_errors, 'PyJWKClientConnectionError'),
    )
    bad_certificates = (
        ValueError,
        TypeError,
        LookupError,
        NotImplementedError,
        OverflowError,
        ImportError,
        AttributeError,
        exceptions.GoogleAuthError,
        *_exception_types(jwt_errors, 'PyJWTError'),
    )
    session = requests.Session()
    cached_session = cachecontrol.CacheControl(session, cache=cache.DictCache())
    request = transport.Request(session=cached_session)

    def certificate_request(presented: str, url: str, **kwargs: object) -> object:
        try:
            response = request(url, **kwargs)
            if response.status != HTTPStatus.OK:
                return response
            certificates = _certificate_entries(response.data, bad_certificates)
        except OSError as exc:
            detail = local_send_detail(exc, session.verify)
            raise _CertificateError(
                f'Google certificate request could not be sent: {detail}'
            ) from None
        except bad_certificates as exc:
            raise _CertificateError(
                f'Google certificate request or decoding failed: {type(exc).__name__}'
            ) from None
        return certificates.response(presented)

    def verify(presented: str) -> Mapping[str, object]:
        try:
            return cast(
                'Mapping[str, object]',
                id_token.verify_oauth2_token(
                    presented, partial(certificate_request, presented), clock_skew_in_seconds=10
                ),
            )
        except outages as exc:
            raise _CertificateError(
                f'Google certificate request failed: {type(exc).__name__}'
            ) from None
        except rejections:
            raise ValueError('Google identity token verification failed') from None

    return verify
