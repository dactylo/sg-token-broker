# Design and security boundaries

sg-token-broker keeps SG script keys in a service instead of distributing them to every tool. It
centralizes token issuance, limits which SG identities each caller can use, and records each
issuance in an audit log. SG remains responsible for enforcing each identity's permissions.

This page explains how the two services decide what to issue and where their protection stops. To
choose a service, read [Choosing a credential](modes.md); to try one, start with the
[quick start](../README.md#quick-start).

## How each service issues a token

### App-token broker

A tool presents its broker client ID and secret with HTTP Basic authentication and names a scope.
The broker verifies the secret against its stored hash, applies the client's per-minute rate limit,
checks the client's scope and token-type allowlists, and returns an SG token for the scope's script
account. SG sees that script account as the caller.

Give each scope a suitably limited SG script account: a scope named `read_all` is read-only only if
its account is. Separate client credentials let you revoke one consuming system without affecting
the others and keep audit records attributable.

The broker reads YAML configuration and runs with `sg-token-broker serve-app-tokens`. See
[app-token broker deployment](deployment.md).

### User-token service

A caller presents an identity-provider ID token. The service verifies it, maps the verified email
address to exactly one SG user, and asks SG for a token bound to that user's login. SG sees the
person as the caller and applies their permissions.

Cloud Run deployments use Google Workspace identity and issue REST tokens. Private deployments can
use Google or a configured OIDC provider and can issue session tokens for `shotgun_api3`. The
service reads environment configuration and runs with `sg-token-broker serve-user-tokens`. See
[User-token service](user-token-service.md).

## What each party holds

| Party                          | Holds                              | Origin                                                              |
| ------------------------------ | ---------------------------------- | ------------------------------------------------------------------- |
| App-token broker               | Each scope's script key            | An SG administrator creates the script account                      |
| User-token service             | Its sudo-capable script key        | An SG administrator creates the script account                      |
| Consuming system               | A broker client ID and secret      | The broker operator runs `hash-secret` and configures only the hash |
| Person using a user-token tool | A sign-in with the studio provider | The identity provider; the `login` extra keeps it in the OS keyring |
| Calling application            | Issued SG tokens                   | The broker or the user-token service, on each request               |

A client secret is a long-lived credential. Anyone who holds it can request tokens for every scope
and token type the client allows, from any host that can reach the broker, until the operator
removes the client. Restricting network access to the broker is what limits a leaked secret; see
[restrict network access](deployment.md#restrict-network-access). Keep secrets on the hosts that
run the consuming system, not in source control or in job settings that other people can read.

Issued SG tokens work wherever SG accepts them. A copied session can outlive both the job and the
removal of its client because activity keeps it alive. Limit clients to REST tokens with
`token_types` when they need a hard expiry; see
[token lifetime and revocation](sg-token-behavior.md).

## Security controls and their limits

| Control                              | Protection                                                           | Limit                                                                              |
| ------------------------------------ | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Central script-key storage           | Callers receive tokens instead of script keys                        | A compromised service host can expose its keys                                     |
| Broker client allowlists             | Each client can request only configured scopes and token types       | SG permissions still depend on the scope's script account                          |
| Hashed broker client secrets         | The configuration stores scrypt hashes                               | A stolen client secret works from any host that can reach the broker until revoked |
| Verified user identity               | Tokens bind to the intended SG user                                  | Provider claims and SG account mapping must be configured correctly                |
| Network restrictions and IAM         | Limit who can reach or invoke a service                              | These controls neither revoke issued tokens nor limit where they work              |
| Token caching with fixed REST expiry | Cache hits do not extend a REST token's lifetime                     | Session tokens follow SG's sliding inactivity lifetime                             |
| Structured audit records             | Attribute issuance and diagnose failures without logging credentials | Applications must also protect their own logs and token storage                    |

For Google deployments, the service checks the ID token's signature, issuer, audience, verified
email, and Workspace domain. Cloud Run IAM adds a separate authorization check before the service
runs. Private session-token deployments rely on their restricted network as the primary
authorization boundary, in addition to the service's identity validation.

## Permissions and attribution

App tokens use the scope's script-account permissions. User tokens use the person's permissions,
including writes their role allows. Neither service adds a read-only limit to either identity, so
SG role configuration remains essential: the broker cannot turn an overprivileged script account or
human account into a read-only identity.

The user-token service needs a dedicated script account that SG allows to act as other users.
Restrict that account's own permissions and keep its key in the service. Its permission role does
not cap the access of the person a token is issued for.

SG can attribute a user session's writes to the person without identifying the script account that
minted the token. Retain the service's audit logs when you need that source attribution.

Code running inside an authorized application can use any credential available to that application.
Restrict who can edit shared Apps Script projects and who can read client secrets.

## Caching and service boundaries

Both services use the same SG token minter, an in-memory token cache, and structured audit logging.
Concurrent requests for the same uncached token share one request to SG. Audit records identify
each token by a fingerprint, never by its value. Because the cache lives in memory, restarting a
service clears it.

The HTTP servers use Python's standard library. Put a TLS reverse proxy in front of a shared
service to control connection rates, slow requests, and network access. The
[broker network guidance](deployment.md#restrict-network-access) lists the built-in limits and the
controls that remain the proxy's job.

## Token lifetime and revocation

Revoking a caller's access to a service stops future issuance; tokens the caller already holds
remain subject to SG's own lifecycle. Session tokens survive script-key rotation, and restoring a
disabled account may make unexpired tokens usable again. The
[token lifetime reference](sg-token-behavior.md) explains expiry, cache hints, and account
suspension. To recover from a leaked script key, follow
[Retire a compromised script account](deployment.md#retire-a-compromised-script-account).
