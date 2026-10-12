#!/usr/bin/env python
"""Cloud Run authentication check: echo the identity Google's edge already verified.

Deploy with --no-allow-unauthenticated and a custom audience, then call it from
a test Sheet via ScriptApp.getIdentityToken() (see the sibling README).
This check decodes the JWT payload WITHOUT signature verification, because
Google's edge has already verified it before this code runs. Never reuse this
pattern in the user-token service, which verifies tokens in-process.
"""

import base64
import binascii
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

_ECHOED_CLAIMS = ('aud', 'email', 'email_verified', 'hd', 'iss')
_JWT_SEGMENT_COUNT = 3


class _Handler(BaseHTTPRequestHandler):
    """Single route: echo the edge-verified caller's claims as JSON."""

    def do_GET(self) -> None:
        """Respond with the claims of the edge-verified caller."""
        claims = _decode_claims_unverified(self.headers.get('Authorization', ''))
        body = json.dumps({'ok': bool(claims), 'claims': claims}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _decode_claims_unverified(authorization: str) -> dict[str, object]:
    """Decode the JWT payload segment without verifying the signature."""
    scheme, _, presented = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not presented:
        return {}
    segments = presented.split('.')
    if len(segments) != _JWT_SEGMENT_COUNT:
        return {}
    payload = segments[1] + '=' * (-len(segments[1]) % 4)
    try:
        decoded: object = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, binascii.Error):
        return {}
    if not isinstance(decoded, dict):
        return {}
    claims = cast('dict[str, object]', decoded)
    return {key: claims.get(key) for key in _ECHOED_CLAIMS}


def main() -> None:
    """Serve on all interfaces using `$PORT`, defaulting to 8080, until terminated."""
    port = int(os.environ.get('PORT', '8080'))
    ThreadingHTTPServer(('', port), _Handler).serve_forever()


if __name__ == '__main__':
    main()
