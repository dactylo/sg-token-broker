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
the script key or an SG refresh token.

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

- **App-token broker:** a session's `expires_at` is advisory. It marks when the broker stops
  reusing its cached session, `defaults.session_ttl_seconds` after minting, and it drives
  `BrokerClient` caching. It does not tell SG when to invalidate the session.
- **User-token service:** a session's `expires_at` is null. `cache_until` is only a hint about how
  long the service may return the same cached session, `SGUT_SESSION_TTL_SECONDS` after minting.
  `UserTokenClient` does not refresh a session based on `cache_until`.

Except for the forced refresh described below, neither service checks with SG before returning a
cached token, so a cached token can already be unusable, for example after an account is disabled.

### Renewing a rejected user session

When SG rejects a user session, call `fetch_token('session', force_refresh=True)`, or run
`sg-token-broker get-user-token --force-refresh`. The service checks its cached session with SG and
replaces it only if SG rejects it. If the service has no live cached entry, it mints a replacement
directly. Recreate the consuming SG client with the returned token.

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
service and client cache handling. Renaming alone is not an established revocation mechanism.

The effect of disabling the source script account on outstanding REST tokens has not been
established. Plan for those tokens to remain usable until their hard expiry.

### Human-account tokens

Disabling the person's SG account rejects new user-bound tokens and suspends outstanding user-bound
REST and session tokens. The service may still return a cached token, but SG rejects its use while
the account is disabled.

| Account state                          | Outstanding REST token                   | Outstanding session token                 |
| -------------------------------------- | ---------------------------------------- | ----------------------------------------- |
| Disabled                               | Rejected                                 | Rejected                                  |
| Restored before the REST token expires | May work again until the original expiry | Restore behavior has not been established |
| Restored after the REST token expires  | Remains expired                          | Restore behavior has not been established |

For permanent offboarding, leave the SG account disabled and revoke the person's access to the
token service. If you restore an account after a REST-token incident, first wait out the
outstanding tokens' full SG lifetime. The service's earlier cache expiry is not the SG revocation
boundary.

## Limits of the supported behavior

This guidance comes from limited testing against SG, not a guarantee for every site configuration
or future Autodesk release. Recheck critical revocation assumptions after material SG
authentication changes. In particular:

- How old user sessions behave after the account is disabled and restored has not been established.
- Disabling a source script account has not been established as a way to revoke REST tokens.
- User permission binding has not been exhaustively checked for every field, conditional rule,
  entity, and create, read, update, or delete operation.
- Legacy password or personal access token authentication for human accounts, and converting a
  session token through a REST grant, are outside the behavior this project has established.

The [revocation check](deployment.md#verify-revocation-behavior-on-a-trial-site) uses a disposable
script account so that you can test your own site's behavior.

## Upstream references

- [REST API authentication](https://developers.shotgridsoftware.com/rest-api/)
- [Python API authentication](https://developers.shotgridsoftware.com/python-api/authentication.html)
- [Python API reference](https://developers.shotgridsoftware.com/python-api/reference.html)
- [Site Preferences and API sessions](https://help.autodesk.com/cloudhelp/ENU/SG-Administrator/files/ar-site-configuration/SG_Administrator_ar_site_configuration_ar_site_preferences_html.html)
- [Autodesk Identity account settings](https://help.autodesk.com/cloudhelp/ENU/SG-Administrator/files/ar-manage-accounts-after-migrating/SG_Administrator_ar_manage_accounts_ar_account_settings_after_migrating_html.html)
