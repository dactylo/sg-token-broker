# Choosing a credential

This page helps you decide which service and token type a tool needs, and shows how a tool requests
each one. If you have not run the broker yet, start with the
[quick start](../README.md#quick-start).

Two questions decide the choice: whose SG permissions the tool should use, and which SG API it
calls.

## Whose permissions

- **App tokens** run SG calls as a script account (an SG `ApiUser`). Use them for farm jobs,
  background services, and tools that share one permission role. The app-token broker issues them.
- **User tokens** run SG calls as the signed-in person's own account (an SG `HumanUser`). Use them
  when SG must enforce that person's permissions and account status. The user-token service issues
  them.

In both cases the long-lived script key stays inside the service; callers receive only tokens.

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

REST tokens stop working at a hard expiry that SG sets. Session tokens follow SG's sliding
inactivity window: active use keeps them alive, and they have no scheduled expiry. That difference
shapes how you handle expiry and how you respond to a leak; see
[token lifetime and revocation](sg-token-behavior.md).

## App tokens

A tool sends its broker client ID and secret with a scope name, such as `artist_read`. A *scope* is
a name in the broker configuration that maps to one SG script account. The broker checks that the
client may use the scope, then returns a token for that script account.

The script account's SG permission role determines what the tool can do; the scope name itself
enforces nothing. Keep scopes narrow, such as `farm_render_read` or `publish_tool_write`, and give
each consuming system its own broker credential. Anyone holding a client credential can request
every scope that client is allowed.

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
token.

## User tokens

The person signs in through the studio identity provider. The user-token service verifies the
resulting ID token, finds the person's SG login, and asks SG for a token bound to that account. The
token carries all of the person's SG permissions, including any writes their role allows; the
service cannot reduce it to read-only. Restrict access through the person's SG permission role.

Choose the deployment that matches the token type:

- **REST:** the Cloud Run deployment serves Google Workspace callers behind Cloud Run IAM and is
  configured with `SGUT_TOKEN_TYPES=rest`.
- **Session:** deploy on a restricted network with its own *sudo-capable* script account (one that
  SG allows to act as other users), `SGUT_TOKEN_TYPES=session`, and a Google or OIDC provider. Do
  not issue session tokens from an internet-facing deployment: a session token has no hard expiry,
  so a leaked one stays usable for as long as someone keeps using it.

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

App-token tools fetch tokens in the background with a provisioned client credential.

Desktop tools that need user tokens sign the person in through the system browser, using the OAuth
authorization code flow with PKCE and a temporary loopback callback. With the optional `login`
extra, the sign-in is stored in the operating system's keyring, so later runs do not open the
browser.

For web applications, prefer fetching SG tokens in the backend after authenticating the user. The
user-token service accepts only Google or configured OIDC ID tokens in the `Authorization` header;
an IAP header alone is not a supported identity input. Give SG tokens to browser JavaScript only
when the application needs direct SG REST access, because any script running in the page can read
them. For Google Sheets, use the [Apps Script caller](user-token-service.md#apps-script-caller).
