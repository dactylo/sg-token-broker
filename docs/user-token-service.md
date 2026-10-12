# User-token service

The user-token service gives a signed-in person an SG token that carries their own SG permissions.
Administrators deploy the service; desktop tools and Google Sheets then exchange the person's
identity-provider ID token for an SG token. To decide whether you need user tokens, read
[Choosing a credential](modes.md); for a first run of the project, start with the
[quick start](../README.md#quick-start).

| If you want to...                                 | Start here                                                                                       |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Deploy for Google Workspace callers that use REST | [Cloud Run REST deployment](#cloud-run-rest-deployment)                                          |
| Deploy for `shotgun_api3` callers                 | [Private session-token deployment](#private-deployment-for-session-tokens)                       |
| Connect a desktop tool to an existing service     | [Desktop client setup](#desktop-client-setup)                                                    |
| Connect a Google Sheet                            | [Apps Script caller](#apps-script-caller)                                                        |
| Diagnose a failed request or read the audit log   | [Operations and troubleshooting](#operations-and-troubleshooting)                                |
| Look up a setting, response field, or status code | [Configuration reference](#configuration-reference) or [HTTP API reference](#http-api-reference) |

For each request, the service verifies the caller's ID token, finds the one SG user whose email
matches the verified address, and asks SG for a token bound to that user's login. It does this with
its own *sudo-capable* script account: an SG script account whose permissions allow it to act as
other users (SG's `sudo_as_login`).

The resulting token has the person's full SG permissions, including writes when their role allows
them. The service has no read-only token scope, so restrict access through the person's SG
permission role. See [permissions and attribution](design.md#permissions-and-attribution).

## Cloud Run REST deployment

This deployment accepts Google Workspace identities, requires Cloud Run IAM authorization, and
issues REST tokens only. It suits Google Sheets and other Google-authenticated callers. For session
tokens, use the [private deployment](#private-deployment-for-session-tokens).

### Prerequisites

You need:

- A Google Cloud project with Cloud Run and Secret Manager available, and a configured `gcloud`
  CLI.
- Access to deploy from this checkout.
- A dedicated sudo-capable SG script account for the service, created by an SG administrator. The
  commands below call it `user_token_service`.
- A Workspace group whose members may call the service. Granting access to a group keeps the
  service from being exposed anonymously.

An SG administrator can confirm the sudo behavior the service relies on with
[`scripts/verify_sg_sudo.py`](../scripts/verify_sg_sudo.py), a standalone companion to
[`scripts/verify_sg_revocation.py`](../scripts/verify_sg_revocation.py) that needs only Python 3.11
or later and `requests`; run it with `--help` for its options.

Set these shell variables to your deployment values before using the commands:

| Variable           | Value                                                          |
| ------------------ | -------------------------------------------------------------- |
| `REGION`           | Cloud Run region                                               |
| `SG_SITE_URL`      | Your SG HTTPS URL                                              |
| `SCRIPT_KEY`       | Application key for the `user_token_service` SG script account |
| `SCRIPT_CLIENT_ID` | The calling Apps Script project's OAuth audience               |
| `WORKSPACE_DOMAIN` | Required Workspace domain, such as `studio.example`            |
| `INVOKER_GROUP`    | Workspace group email for authorized callers                   |
| `RUNTIME_SA`       | Runtime service-account email                                  |

### Find the Apps Script audience

Cloud Run and the service both check the ID token's audience, which for an Apps Script caller is
the project's OAuth client ID. Add the [Apps Script manifest](#apps-script-caller) to the project
so it can request identity tokens. Then run this function in the Apps Script editor; it logs the
audience, not the token:

```javascript
function logIdentityAudience() {
  const token = ScriptApp.getIdentityToken();
  const payload = Utilities.newBlob(
    Utilities.base64DecodeWebSafe(token.split('.')[1])
  ).getDataAsString();
  Logger.log(JSON.parse(payload).aud);
}
```

Set `SCRIPT_CLIENT_ID` to the logged value.

### Cloud Run authentication check

Before deploying the token service, confirm that Cloud Run accepts the script's identity tokens and
rejects callers outside the invoker group. This repository includes a small check service that
echoes the caller's identity claims and needs no SG key, so a misconfiguration exposes nothing. Use
the same region, audience, and invoker group that you plan for the token service. From the
repository root:

```sh
gcloud run deploy sg-token-auth-check \
    --source scripts/cloud_run_auth_check \
    --region "$REGION" \
    --no-allow-unauthenticated \
    --add-custom-audiences "$SCRIPT_CLIENT_ID"
gcloud run services add-iam-policy-binding sg-token-auth-check \
    --region "$REGION" \
    --member "group:$INVOKER_GROUP" \
    --role roles/run.invoker
```

In a test Sheet with the [identity-token manifest](#apps-script-caller), set the check service's
deployed URL and run:

```javascript
function checkServiceAccess() {
  const response = UrlFetchApp.fetch('https://sg-token-auth-check-HASH.run.app', {
    headers: { Authorization: 'Bearer ' + ScriptApp.getIdentityToken() },
    muteHttpExceptions: true,
  });
  Logger.log(response.getResponseCode());
  Logger.log(response.getContentText());
}
```

Verify both outcomes before you continue:

1. A group member receives HTTP 200 and their own email in the echoed claims.
2. A non-member running the same script receives HTTP 403, and the check service logs no matching
   request, which shows that Cloud Run stopped it. A 401 means Cloud Run rejected the token itself,
   so it does not show that group membership is enforced.

Use an Apps Script token for both checks. A token from `gcloud auth print-identity-token` has a
different audience and does not test this caller path. If either check fails, fix the identity or
IAM configuration before deploying the token service. When both pass, delete the check service:

```sh
gcloud run services delete sg-token-auth-check --region "$REGION"
```

### Store the key and deploy

Create the secret:

```sh
printf '%s' "$SCRIPT_KEY" | gcloud secrets create sg-user-token-key --data-file=-
```

Use a dedicated runtime service account and grant it access to that secret:

```sh
gcloud secrets add-iam-policy-binding sg-user-token-key \
    --member "serviceAccount:$RUNTIME_SA" \
    --role roles/secretmanager.secretAccessor
```

From the repository root, deploy the Dockerfile with the same audience that the caller uses:

```sh
gcloud run deploy sg-user-tokens \
    --source . \
    --region "$REGION" \
    --service-account "$RUNTIME_SA" \
    --no-allow-unauthenticated \
    --add-custom-audiences "$SCRIPT_CLIENT_ID" \
    --set-secrets "SGUT_SCRIPT_KEY=sg-user-token-key:latest" \
    --set-env-vars "SGUT_SITE_URL=$SG_SITE_URL" \
    --set-env-vars "SGUT_SCRIPT_NAME=user_token_service" \
    --set-env-vars "SGUT_AUDIENCES=$SCRIPT_CLIENT_ID" \
    --set-env-vars "SGUT_TOKEN_TYPES=rest" \
    --set-env-vars "SGUT_ALLOWED_DOMAIN=$WORKSPACE_DOMAIN"
```

Authorize the caller group:

```sh
gcloud run services add-iam-policy-binding sg-user-tokens \
    --region "$REGION" \
    --member "group:$INVOKER_GROUP" \
    --role roles/run.invoker
```

Set the deployed URL in the [Apps Script caller](#apps-script-caller) and verify an SG request as
an authorized user whose email matches an active SG account. Consumer Google accounts are rejected
with HTTP 401 because they carry no Workspace `hd` claim; that claim must match
`SGUT_ALLOWED_DOMAIN`.

To accept another Apps Script project or app later, add its audience to both
`--add-custom-audiences` and `SGUT_AUDIENCES`. Cloud Run accepts only tokens issued for its own URL
or a listed custom audience, and the service checks the audience again itself.

## Private deployment for session tokens

Session tokens work with `shotgun_api3` but have no hard expiry, so a leaked session token can stay
usable for as long as someone keeps using it. Run a session-token service only where trusted
networks can reach it; that network boundary is the primary authorization gate for session
issuance. Keep Cloud Run deployments REST-only.

The same container image runs on any platform that supplies environment variables, with a
Kubernetes ingress or reverse proxy terminating TLS. Configure the deployment as follows:

- **Token types:** set `SGUT_TOKEN_TYPES=session`. The service issues only the token types listed,
  so a REST deployment cannot mint sessions, and a session deployment need not mint REST tokens.
- **Network access:** limit access to trusted networks through private ingress or VPN-only routing.
  The service listens on all interfaces at `PORT`, so a host firewall must reject direct
  connections to `PORT` from anything except the TLS proxy. For a proxy on the same host, allow
  connections from loopback only.
- **Script account:** give this deployment its own minimal sudo-capable script account, separate
  from any Cloud Run deployment's, so that you can retire one deployment's account after a
  compromise without breaking the other.
- **Trusted proxies:** set `SGUT_TRUSTED_PROXIES` to the TLS proxy's peer addresses. The service
  honors `X-Forwarded-For` only from listed peers, so callers cannot forge the source address
  recorded in audit logs. It records the last address in that header, which the proxy appends.
  Addresses are compared as parsed IP addresses, so equivalent IPv6 forms and IPv4-mapped IPv6
  addresses match. This setting controls which forwarded addresses are trusted, not which peers may
  connect.

A private deployment can use Google Workspace identity, as on Cloud Run, or a generic OIDC provider
such as Okta, Microsoft Entra ID, Auth0, or Keycloak. For OIDC, set `SGUT_PROVIDER=oidc` and set
`SGUT_ISSUER` to the provider's exact issuer URL. The configured email claim must be unique and
immutable for each user in that provider, because the service maps it to an SG account. Enable
`SGUT_ASSUME_EMAIL_VERIFIED` only when the provider asserts verified addresses without including an
`email_verified` claim.

The Dockerfile installs both provider extras and starts `serve-user-tokens`. Outside the container,
install from a checkout with `uv tool install '.[google]'` or `uv tool install '.[oidc]'` for your
provider. Supply every required setting from the
[configuration reference](#configuration-reference), with the script key from your deployment's
secret store. For example, a Google session service on the same host as its TLS proxy needs:

```sh
export SGUT_SITE_URL='https://your-site.shotgrid.autodesk.com'
export SGUT_SCRIPT_NAME='private_user_token_service'
export SGUT_SCRIPT_KEY='your-private-service-script-key'
export SGUT_AUDIENCES='installed-app-client-id'
export SGUT_ALLOWED_DOMAIN='studio.example'
export SGUT_TOKEN_TYPES='session'
export SGUT_PROVIDER='google'
export SGUT_TRUSTED_PROXIES='127.0.0.1'
export PORT='8080'
sg-token-broker serve-user-tokens
```

Replace the example proxy address with the proxy's actual peer addresses. In this same-host layout,
the host firewall must allow the TLS proxy to reach port 8080 over loopback and reject connections
to that port from other interfaces. Configure connection limits and timeouts at the proxy.

On startup, the service prints `serving user tokens on port 8080`. A successful `GET /healthz`
checks only the listener, so verify a sign-in and an SG token request before giving clients access.
Session responses have no hard expiry; read [token lifetime and revocation](sg-token-behavior.md)
before deciding how clients handle rejected tokens and how you offboard people.

## Desktop client setup

Ask the service administrator for the service's HTTPS URL, the token type it issues, the
installed-app OAuth client ID, and, for a provider other than Google, the provider's issuer URL. A
session request needs a private session-token service; the REST-only Cloud Run service rejects it.

Administrators register that OAuth client as an installed (native) app that allows loopback
redirects to `http://127.0.0.1:<port>/callback`; the CLI listens on a new free port for each
sign-in. The service's `SGUT_AUDIENCES` must include the client ID, because the ID token's audience
is the client that requested it. For stored sign-in through an OIDC provider, the client must also
be allowed the `offline_access` scope.

From a checkout, install the CLI with persistent sign-in support and point it at the service:

```sh
uv tool install '.[login]'
export SG_USER_TOKEN_URL='https://user-token-service.example.invalid'
export SG_USER_TOKEN_CLIENT_ID='installed-app-client-id'
```

Google is the default provider. For another OIDC provider, also set its exact issuer URL:

```sh
export SG_USER_TOKEN_ISSUER='https://identity.example.invalid'
```

Sign in through the system browser, then request the token type your service issues:

```sh
sg-token-broker login
sg-token-broker get-user-token --token-type session
```

`login` prints `signed in as` followed by the account name. `get-user-token` prints JSON with
`token`, `token_type`, `login`, `site_url`, `expires_at` (null for a session), and `cache_until`.
It requests a session token unless you pass `--token-type rest`, and opens the browser itself when
no stored sign-in is available.

With the `login` extra, `login` stores a refresh credential in the operating system's keyring, so
later commands and processes do not open the browser. Only the macOS Keychain, the Linux Secret
Service, and the Windows Credential Manager are used. With any other keyring, or without the extra,
`login` reports `(credential not stored)`, and later commands open the browser again.
`login --no-store` signs in without storing a credential, for shared or ephemeral machines.

Each stored credential is named after the account that `login` printed: the value of the ID-token
claim named by `SG_USER_TOKEN_EMAIL_CLAIM` (default `email`), else `sub`, else `unknown`. Commands
use the most recently signed-in account unless `SG_USER_TOKEN_ACCOUNT` names another stored
account. This name only selects a local credential; the service separately requires a verified
email that meets its provider and domain policy. `sg-token-broker logout` removes the selected
account's stored credential. It does not revoke SG tokens already issued.

Python applications use `UserTokenClient`, which reads the same environment variables; see
[user tokens](modes.md#user-tokens) for an example, and install the package in the application's
own Python environment. The client checks the current sign-in on every `fetch_token` call and
reuses a cached SG token only while the ID token's `sub` claim matches the identity that obtained
it, so switching accounts takes effect on the next call. It requests a new REST token 60 seconds
before `expires_at`, and keeps a session until you pass `force_refresh=True`.

## Apps Script caller

The manifest (`appsscript.json`) must include these scopes, or `ScriptApp.getIdentityToken()`
returns null:

```json
{
  "oauthScopes": [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/script.external_request"
  ]
}
```

This caller fetches a token without prompting the user and fetches a new one after `expires_at`. It
stores tokens with `CacheService.getUserCache()`, which keeps each person's token separate.
`getScriptCache()` shares one cache across users and could give one person's token to another user
of the Sheet:

```javascript
const SERVICE_URL = 'https://sg-user-tokens-HASH.run.app';

function sgFetch(path) {
  const sg = fetchSgToken();
  return UrlFetchApp.fetch(sg.site_url + path, {
    headers: { Authorization: 'Bearer ' + sg.token },
  });
}

function fetchSgToken() {
  const cache = CacheService.getUserCache();
  const cached = cache.get('sg');
  if (cached) {
    const parsed = JSON.parse(cached);
    if (new Date(parsed.expires_at) > new Date()) return parsed;
  }
  const idToken = ScriptApp.getIdentityToken();
  const response = UrlFetchApp.fetch(SERVICE_URL + '/v1/user-token', {
    headers: { Authorization: 'Bearer ' + idToken },
  });
  const sg = JSON.parse(response.getContentText());
  cache.put('sg', JSON.stringify(sg), 500);
  return sg;
}
```

Restrict edit access to the Sheet's container-bound script. Anyone who can edit it could change it
to collect tokens from people who open the Sheet.

## Operations and troubleshooting

- **Suspend a person's SG access:** disable their SG account, and remove their access to the
  service to stop future issuance. Restoring an account can revive REST tokens that have not yet
  expired, and old session behavior after restoration is not established; see
  [human-account tokens](sg-token-behavior.md#human-account-tokens).
- **Rotate or replace the service key:** update the secret-store version, then restart the service
  or deploy a new Cloud Run revision; the service reads `SGUT_SCRIPT_KEY` only at startup. Key
  rotation does not revoke existing sessions. Give each deployment its own script account, and
  after a compromise follow
  [Retire a compromised script account](deployment.md#retire-a-compromised-script-account).
- **Every caller receives 502:** check the service script key and its Secret Manager version first.
  An invalid key is logged as an `error` event with reason `upstream_error`. For REST requests, an
  SG REST token lifetime of 150 seconds or less also causes 502, with the `detail`
  `SG token lifetime too short to serve`: the service reuses each REST token for up to 120 seconds
  and keeps a 30-second margin before its expiry.
- **A caller receives 401:** Cloud Run or the service rejected the ID token. When the service
  rejected it, the audit record's `detail` names the failed check, such as `audience not accepted`,
  `email domain not allowed`, or `email is not verified`.
- **A caller receives 403:** check that the person has an active SG account with a matching email,
  that the deployment issues the requested token type, and, on Cloud Run, that the person is in the
  invoker group. A service `deny` event with reason `forbidden` means the deployment does not issue
  that token type, no single SG user matches the email, or SG refused to issue a token for that
  user, for example because the account is disabled. A 403 with no service event came from Cloud
  Run IAM.
- **A caller receives 500:** if the identity provider fails while the service verifies a token, the
  service returns an opaque 500 rather than 401, so that a provider outage is not reported as a
  rejected identity. Inspect the server logs for the cause.
- **Additional egress restriction:** a static Cloud NAT address can support an SG-side IP allowlist
  for the service's script account.

### Audit logs

The service writes one JSON line to standard output for each issuance, denial, or error; Cloud Run
collects these. `token_fp` is the first 16 hexadecimal characters of the token's SHA-256 digest,
which lets you match a found token to its issuance without logging the token itself.

| Event                               | Fields                                                                                               |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Issue                               | `ts`, `event`, `email`, `login`, `aud`, `token_fp`, `cache`, `source_ip`, `request_id`, `token_type` |
| Identity rejection                  | `ts`, `event`, `reason`, `detail`, `source_ip`, `request_id`, `token_type`                           |
| Post-authentication denial or error | `ts`, `event`, `email`, `aud`, `reason`, `detail`, `source_ip`, `request_id`, `token_type`           |
| Pre-service denial                  | `ts`, `event`, `reason`, `source_ip`, `request_id`                                                   |
| Unhandled error                     | `ts`, `event`, `reason`, `detail`, `source_ip`, `request_id`, `token_type`                           |

- `event` is `issue`, `deny`, or `error`.
- `cache` is `hit` for a reused token, `miss` for a newly minted one, and `kept` when a forced
  refresh found the cached session still valid.
- `reason` comes from a fixed set: `unauthorized`, `forbidden`, `bad_request`, `not_found`,
  `method_not_allowed`, `upstream_error`, or `internal_error`.
- An unrecognized `token_type` is recorded as `invalid`.

The startup line `serving user tokens on port ...` goes to standard error and can appear at ERROR
severity in Cloud Logging even after a successful start. Stack traces for unexpected errors are
plain text on standard output and can appear as separate INFO entries; search for
`unhandled error issuing user token` when investigating a 500.

## Configuration reference

The service reads its configuration from environment variables at startup.

| Variable                     | Default             | Description                                                                                                  |
| ---------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------ |
| `SGUT_SITE_URL`              | Required            | SG site URL. It must use HTTPS; plain HTTP is accepted only for a loopback host.                             |
| `SGUT_SCRIPT_NAME`           | Required            | Name of the service's sudo-capable script account.                                                           |
| `SGUT_SCRIPT_KEY`            | Required            | That script account's application key. Supply it from a secret store.                                        |
| `SGUT_AUDIENCES`             | Required            | Comma-separated ID-token audiences to accept.                                                                |
| `SGUT_ALLOWED_DOMAIN`        | Required            | Email domain that callers must belong to. Google tokens must also carry a matching `hd` claim.               |
| `SGUT_TOKEN_TYPES`           | Required            | Comma-separated token types this deployment issues: `rest`, `session`, or both.                              |
| `SGUT_PROVIDER`              | `google`            | Identity provider: `google` or `oidc`.                                                                       |
| `SGUT_ISSUER`                | Required for `oidc` | OIDC issuer URL, using HTTPS except on a loopback host. It is compared exactly, so a trailing slash matters. |
| `SGUT_EMAIL_CLAIM`           | `email`             | OIDC only: the ID-token claim that holds the user's email address.                                           |
| `SGUT_ASSUME_EMAIL_VERIFIED` | `false`             | OIDC only: `true` accepts addresses from tokens that have no `email_verified` claim.                         |
| `SGUT_OIDC_ALGORITHMS`       | `ES256,RS256`       | OIDC only: comma-separated asymmetric signature algorithms to accept.                                        |
| `SGUT_SESSION_TTL_SECONDS`   | `600`               | Positive integer: how long the service reuses a cached session token.                                        |
| `SGUT_TRUSTED_PROXIES`       | Empty               | Comma-separated proxy IP addresses whose `X-Forwarded-For` header the service trusts.                        |
| `PORT`                       | `8080`              | Listening port. Cloud Run sets it.                                                                           |

`SGUT_OIDC_ALGORITHMS` accepts `ES256`, `ES384`, `ES512`, `EdDSA`, `PS256`, `PS384`, `PS512`,
`RS256`, `RS384`, and `RS512`. `SGUT_ALLOWED_DOMAIN` is compared without regard to case, and a
leading `@` is ignored.

## HTTP API reference

`GET /v1/user-token` exchanges the caller's ID token, sent as `Authorization: Bearer <ID token>`,
for an SG token. The service reads the caller's identity only from this header. It accepts two
query parameters, each at most once:

- `token_type`: `rest` or `session`. Omitting it or leaving it empty selects `rest`. The deployment
  must issue the requested type.
- `refresh`: only the exact value `true` asks the service to check its cached session with SG and
  replace it if SG rejects it. Any other value counts as false.

A successful response contains these fields:

| Field         | Meaning                                                                                                   |
| ------------- | --------------------------------------------------------------------------------------------------------- |
| `token`       | The SG token, bound to the caller's own SG user                                                           |
| `token_type`  | `rest` or `session`                                                                                       |
| `login`       | The caller's SG login                                                                                     |
| `site_url`    | The SG site to call                                                                                       |
| `expires_at`  | For REST, the expiry to rely on: SG's lifetime minus a 30-second margin. Null for a session.              |
| `cache_until` | Equal to `expires_at` for REST. For a session, a hint for how long the service may return the same token. |

Errors return JSON with `error` and `detail` fields. For a 400, `detail` describes the problem; for
other errors it stays generic, and the specific cause goes to the server logs.

| Status | `error`              | Meaning                                                                                               |
| ------ | -------------------- | ----------------------------------------------------------------------------------------------------- |
| 400    | `bad_request`        | Unknown or repeated query parameter, a `token_type` other than `rest` or `session`, or a request body |
| 401    | `unauthorized`       | The service rejected the caller's ID token                                                            |
| 403    | `forbidden`          | The deployment does not issue that token type, no single SG user matches, or SG refused the user      |
| 404    | `not_found`          | Unknown path                                                                                          |
| 405    | `method_not_allowed` | Unsupported method                                                                                    |
| 500    | `internal_error`     | The identity provider failed during verification, or an unexpected error occurred                     |
| 502    | `upstream_error`     | An SG request failed                                                                                  |

Correct the request before retrying a 400. On Cloud Run, IAM can also answer 401 or 403, with its
own body, before a request reaches the service.

`GET /healthz` answers `{"status": "ok"}`.

For expiry, renewal, and offboarding, see [token lifetime and revocation](sg-token-behavior.md).
