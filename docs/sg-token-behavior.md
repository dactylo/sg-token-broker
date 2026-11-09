# Token lifetime and revocation

Use this reference when handling token expiry, deciding how long a token can be reused, or
responding to a leaked credential. To choose a token type, read [Choosing a credential](modes.md);
for a first run, start with the [quick start](../README.md#quick-start).

## At a glance

| Token              | SG identity                | Interface                 | Lifetime                    |
| ------------------ | -------------------------- | ------------------------- | --------------------------- |
| App session token  | Scope's script account     | `shotgun_api3` / JSON-RPC | Sliding site session window |
| App REST token     | Scope's script account     | REST                      | Hard expiry set by SG       |
| User session token | Signed-in person's account | `shotgun_api3` / JSON-RPC | Sliding site session window |
| User REST token    | Signed-in person's account | REST                      | Hard expiry set by SG       |

A REST bearer token cannot replace a session token in `shotgun_api3`. Neither service gives callers
the script key or an SG refresh token. A session token needs no refresh token: it stays usable for
as long as it is in use.

## REST expiry

A REST token stops working at its hard expiry, and reusing a cached token does not extend that
expiry. Read the response's `expires_at` instead of assuming a fixed duration: SG sets the
lifetime, and each service subtracts a safety margin so that callers replace the token before SG
rejects it. The app-token broker subtracts 60 seconds; the user-token service subtracts 30 seconds.

The user-token service also returns `cache_until`, which equals `expires_at` for REST tokens.
Because callers never receive an SG refresh token, a replacement always requires a new request to
the service; a user-token caller must present a current ID token again. The client libraries
request a replacement 60 seconds before `expires_at`.

## Session lifetime and cache hints

SG sessions follow the site's User Session Expiry setting. Activity extends the inactivity window,
and a service's cache duration does not impose a hard expiry on the SG session itself.

The two services report session deadlines differently:

| Service            | Session `expires_at`                   | Cache duration                                                            | Client behavior                                                                    |
| ------------------ | -------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| App-token broker   | Advisory cache deadline, not SG expiry | `defaults.session_ttl_seconds` after minting                              | `BrokerClient` uses `expires_at` to decide when to request another token           |
| User-token service | Null                                   | `cache_until` hints at reuse for `SGUT_SESSION_TTL_SECONDS` after minting | `UserTokenClient` ignores `cache_until` and keeps the session until forced refresh |

Except for the forced user-session refresh described below, neither service checks with SG before
returning a cached token, so a cached token can already be unusable, for example after an account
is disabled.

### Renewing a rejected user session

When SG rejects a user session, call `fetch_token('session', force_refresh=True)`, or run
`sg-token-broker get-user-token --force-refresh`. The service checks its cached session with SG and
replaces it only if SG rejects it. If the service has no live cached entry, it mints a replacement
directly. Recreate the consuming SG client with the returned token.

### Replacing a rejected app token

When SG rejects an app token before its `expires_at`, call
`BrokerClient.fetch_token(scope, token_type, force_refresh=True)`. The client discards its cached
token and asks the broker again. The broker does not check its own cache with SG: it can return the
same REST token for up to 60 seconds after minting it, and the same session for
`defaults.session_ttl_seconds`. If the returned token is the one SG rejected, wait before retrying.

## Revocation

Removing a broker client or revoking a person's access to the user-token service stops future
issuance once the configuration or IAM change takes effect. It does not invalidate tokens the
caller already holds. The project provides no supported way to revoke an individual token in SG.

### Script-account sessions

Session tokens remain valid after their script account's application key is rotated. Trashing the
account suspends them, but restoring the same account can make them usable again.

To retire a compromised account's sessions, rotate its key, rename the account, trash it and leave
it trashed, then create a replacement account with the original name and a fresh key. Follow the
[full recovery procedure](deployment.md#retire-a-compromised-script-account), which includes
service and client cache handling. Do not rely on renaming alone to revoke a token.

For outstanding app REST tokens, plan for use until hard expiry even after disabling the source
script account. Do not rely on that action to revoke them.

### Human-account tokens

Disabling the person's SG account rejects new user-bound tokens and suspends outstanding user-bound
REST and session tokens. The service may still return a cached token, but SG rejects its use while
the account is disabled.

Restoring an account before a REST token expires can make that token usable again until its
original expiry. A REST token that has expired stays expired. Do not rely on disabling and
restoring an account to retire its old sessions.

For permanent offboarding, leave the SG account disabled and revoke the person's access to the
token service. If you restore an account after a REST-token incident, first wait out the
outstanding tokens' full SG lifetime. The service's earlier cache expiry is not the SG revocation
boundary.

## Supported authentication paths

Use the [app-token broker or user-token service](modes.md) to obtain session or REST tokens. Legacy
human-account password or personal access token authentication, and converting a session token
through a REST grant, are outside this project's supported authentication paths.

For account recovery, the
[revocation check](deployment.md#verify-revocation-behavior-on-a-trial-site) lets an administrator
check a site's behavior with a disposable script account. Use it after material SG authentication
changes.

## Upstream references

- [REST API authentication](https://developers.shotgridsoftware.com/rest-api/)
- [Python API authentication](https://developers.shotgridsoftware.com/python-api/authentication.html)
- [Python API reference](https://developers.shotgridsoftware.com/python-api/reference.html)
- [Site Preferences and API sessions](https://help.autodesk.com/cloudhelp/ENU/SG-Administrator/files/ar-site-configuration/SG_Administrator_ar_site_configuration_ar_site_preferences_html.html)
- [Autodesk Identity account settings](https://help.autodesk.com/cloudhelp/ENU/SG-Administrator/files/ar-manage-accounts-after-migrating/SG_Administrator_ar_manage_accounts_ar_account_settings_after_migrating_html.html)
