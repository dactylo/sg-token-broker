# Changelog

## 0.2.0 (2026-11-08)

### Breaking changes

- The broker no longer loads a configuration that contains keys it does not define, such as a
  misspelled `token_types`. Before you restart the broker on this release, run
  `sg-token-broker check-config` and remove or correct each key it reports.
- `hash-secret --secret` no longer takes the secret as an argument. Enter it at the prompt, or pipe
  it to standard input.

### Added

- Broker clients can be limited to certain token types with `token_types`, set per client or under
  `defaults`. The broker rejects requests for any other type with HTTP 403.
- `BrokerClient.fetch_token()` accepts `force_refresh=True`, which skips the client's cache and
  asks the broker again after SG rejects a token.
- `SGUT_BIND` sets the address the user-token service listens on, such as `127.0.0.1` behind a TLS
  proxy on the same host.

### Changed

- Errors from `BrokerClient`, `UserTokenClient`, and the client commands include the reason the
  broker, user-token service, or identity provider gave.
- `login` says why it did not store your sign-in, such as a missing keyring.

### Fixed

- Signing in through Google no longer fails with `code exchange rejected (HTTP 400)`. Set
  `SG_USER_TOKEN_CLIENT_SECRET` to your Desktop app OAuth client's secret.
- `BrokerClient` no longer raises an error when the broker is unavailable or rate limiting in the
  minute before a cached token expires; it keeps using the token until it expires.
- `UserTokenClient` no longer opens the browser for every token request when it has no stored
  sign-in to refresh, such as when the identity provider does not allow `offline_access`. Each
  process signs in once.
- A missing or unreadable CA bundle, from `--ca-bundle` or `REQUESTS_CA_BUNDLE`, is reported as an
  error instead of a traceback.

## 0.1.0 (2026-10-11)

Initial release.
