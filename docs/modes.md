# Choosing a credential

This page helps you decide which service and token type a tool needs, and shows how a tool requests
each one. If you have not run the broker yet, start with the
[quick start](../README.md#quick-start).

Choose in two steps: whose SG permissions the tool needs, then which API it calls.

## Whose permissions

| Use         | When the tool needs                                           | SG identity                    | Service            |
| ----------- | ------------------------------------------------------------- | ------------------------------ | ------------------ |
| App tokens  | A shared permission role for farm jobs or background services | Script account (`ApiUser`)     | App-token broker   |
| User tokens | The signed-in person's permissions and account status         | Person's account (`HumanUser`) | User-token service |

In both cases the long-lived script key stays inside the service. An app-token caller holds a
broker client credential instead, and a user-token caller signs in as the person.

## Which token type

The SG Python API (`shotgun_api3`) uses JSON-RPC and needs a session token. The SG REST API needs a
REST token, sent as a bearer token. The two are not interchangeable: a REST token cannot be passed
as `session_token` to `shotgun_api3`.

| Permissions | API used by the tool      | Token              | Deploy with                                                                                     |
| ----------- | ------------------------- | ------------------ | ----------------------------------------------------------------------------------------------- |
| App         | `shotgun_api3` / JSON-RPC | App session token  | [App-token broker](deployment.md)                                                               |
| App         | REST                      | App REST token     | [App-token broker](deployment.md)                                                               |
| User        | REST                      | User REST token    | [Cloud Run REST deployment](user-token-service.md#cloud-run-rest-deployment)                    |
| User        | `shotgun_api3` / JSON-RPC | User session token | [Private session-token deployment](user-token-service.md#private-deployment-for-session-tokens) |

Prefer REST tokens when the tool does not need `shotgun_api3`: SG stops accepting them at a hard
expiry. Session tokens use a sliding inactivity window, so active use can keep a leaked token alive
indefinitely. See [token lifetime and revocation](sg-token-behavior.md) for expiry and recovery.

## App tokens

A tool sends its broker client ID and secret with a scope name, such as `artist_read`. A *scope* is
a name in the broker configuration that maps to one SG script account. The broker checks that the
client may use the scope and token type, then returns a token for that script account.

The script account's SG permission role determines what the tool can do; the scope name itself
enforces nothing. Keep scopes narrow, such as `farm_render_read` or `publish_tool_write`, and give
each consuming system its own broker credential. Anyone holding a client credential can request
every scope and token type that client is allowed. If a client's tools do not use `shotgun_api3`,
limit it to REST tokens with [`token_types`](deployment.md#configuration-reference).

An application may record who launched it, but SG attributes its requests to the script account.
Choose user tokens when SG itself needs the person's identity.

After [configuring the client environment](deployment.md#configure-client-environments), a Python
tool can use:

```python
import shotgun_api3

from sg_token_broker import BrokerClient

token = BrokerClient().fetch_token('artist_read')
sg = shotgun_api3.Shotgun(token.site_url, session_token=token.token)
```

For REST, call `fetch_token('artist_read', 'rest')` and send the token to SG in an
`Authorization: Bearer` header. The broker never gives callers the script key or an SG refresh
token. If SG rejects a token before its `expires_at`, see
[replacing a rejected app token](sg-token-behavior.md#replacing-a-rejected-app-token).

## User tokens

The person signs in through the studio identity provider. The user-token service verifies the
resulting ID token, finds the person's SG login, and asks SG for a token bound to that account. The
token carries all of the person's SG permissions, including any writes their role allows; the
service cannot reduce it to read-only. Restrict access through the person's SG permission role.

Choose the deployment that matches the token type:

| Token type | Deployment boundary        | Identity provider        | Setting                    |
| ---------- | -------------------------- | ------------------------ | -------------------------- |
| REST       | Cloud Run IAM              | Google Workspace         | `SGUT_TOKEN_TYPES=rest`    |
| Session    | Restricted private network | Google Workspace or OIDC | `SGUT_TOKEN_TYPES=session` |

Each deployment needs its own *sudo-capable* script account: one SG allows to act as other users.
Do not issue session tokens from an internet-facing deployment, because they have no hard expiry.

For desktop tools, follow [desktop client setup](user-token-service.md#desktop-client-setup). An
application with this package and `shotgun_api3` installed can then use:

```python
import shotgun_api3

from sg_token_broker import UserTokenClient

token = UserTokenClient().fetch_token('session')
sg = shotgun_api3.Shotgun(token.site_url, session_token=token.token)
```

Reuse the session until SG rejects it. Then call `fetch_token('session', force_refresh=True)` and
create a new SG client with the returned token. See
[renewing a rejected user session](sg-token-behavior.md#renewing-a-rejected-user-session) for what
the service checks before it replaces a session.

Disabling the person's SG account suspends their tokens. Before offboarding someone, read
[human-account tokens](sg-token-behavior.md#human-account-tokens).

## Desktop and web integration

App-token tools are unattended processes on hosts you control, and they fetch tokens with a
provisioned client credential. Do not give a client credential to tools that people run on their
own workstations: anyone who can use the workstation can read it and act as the script account, and
SG cannot tell those people apart. Give such tools user tokens instead.

Desktop tools that need user tokens sign the person in through the system browser, using the OAuth
authorization code flow with PKCE and a temporary loopback callback. With the optional `login`
extra, the sign-in is stored in the operating system's keyring, so later runs do not open the
browser.

For web applications, prefer fetching SG tokens in the backend after authenticating the user. The
user-token service accepts only Google or configured OIDC ID tokens in the `Authorization` header;
an IAP header alone is not a supported identity input. Give SG tokens to browser JavaScript only
when the application needs direct SG REST access, because any script running in the page can read
them. For Google Sheets, use the [Apps Script caller](user-token-service.md#apps-script-caller).
