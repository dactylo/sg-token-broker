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
rejects it. The app-token broker subtracts 60 seconds and refuses an SG lifetime of 60 seconds or
less. The user-token service subtracts 30 seconds and also requires the remainder to exceed its
120-second cache duration.

The user-token service also returns `cache_until`, which equals `expires_at` for REST tokens.
Because callers never receive an SG refresh token, a replacement always requires a new request to
the service; a user-token caller must present a current ID token again. On the next use near
expiry, the user client requests a replacement within its refresh margin (default 60 seconds). The
app client spreads its first refresh across the preceding minute. See
[client tuning and retries](deployment.md#client-tuning-and-retries).

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

Keep one `BrokerClient` and call `broker.fetch_token(scope, token_type, rejected_token=t)`, where
`t` is the exact token SG rejected. Rebuild the SG connection with the returned token. The client
remembers the eight most recently reported distinct token digests per scope and token type, each
for 24 hours from its latest report. It sends that history on subsequent requests, including forced
refreshes. The broker replaces a matching cached token, reuses a different live token, or mints if
its cache is empty. A failed replacement leaves the rejected entry evicted.

A broker that returns a token named in the report triggers
`broker returned a token already reported rejected; upgrade every broker to 0.3.0`. With no
rejection history, `force_refresh=True` discards the local entry and asks again. The broker may
return the same token.

For shell callers, each invocation starts with no history. Keep the eight most recently rejected
distinct tokens for this client, scope and type. Supply them on standard input, one per line, for
example from a file readable only by the job account:

```sh
sg-token-broker get-token --scope read_all --replace-rejected <rejected-tokens.txt
```

Blank lines are ignored. Empty input performs an ordinary fetch. More than eight nonblank lines are
an error. The command refuses interactive input and shows how to redirect it. Never pass token
values as arguments, which other processes can see. Replacement-mode usage errors omit misplaced
arguments, and broker errors redact the submitted tokens. Protect the returned JSON as a
credential.

A retry behind a proxy can reach a different broker process with its own cached token. Recovery is
guaranteed across up to eight processes. Report each token SG actually rejects and bound the number
of reads as in the [migration example](migrating.md#recover-a-read-when-sg-rejects-the-session).

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
