# App-token broker deployment

This guide is for operators who run the app-token broker for shared use. The broker issues SG
tokens for configured script accounts to the farm jobs, pipeline services, and tools you register
as clients. The steps use Linux, systemd, and a TLS reverse proxy. For a first run on your own
machine, use the [quick start](../README.md#quick-start); for tokens that carry a person's own SG
permissions, use the [user-token service guide](user-token-service.md).

| If you want to...                                      | Start here                                                                                       |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Install the broker on a Linux host                     | [Install the broker](#install-the-broker)                                                        |
| Create the SG script accounts behind each scope        | [Create SG script accounts](#create-sg-script-accounts)                                          |
| Issue a credential to a consuming system               | [Create broker clients](#create-broker-clients)                                                  |
| Write or change the broker configuration               | [Write the configuration](#write-the-configuration)                                              |
| Run the broker as a service                            | [Run the broker with systemd](#run-the-broker-with-systemd)                                      |
| Put the broker behind TLS and restrict access          | [Restrict network access](#restrict-network-access)                                              |
| Point a farm job or tool at the broker                 | [Configure client environments](#configure-client-environments)                                  |
| Rotate a secret, revoke a client, or respond to a leak | [Operations](#operations)                                                                        |
| Trace a token or investigate a denial                  | [Audit logs](#audit-logs)                                                                        |
| Test how your SG site revokes sessions                 | [Verify revocation behavior](#verify-revocation-behavior-on-a-trial-site)                        |
| Look up a configuration key or HTTP status             | [Configuration reference](#configuration-reference) or [HTTP API reference](#http-api-reference) |

Read the [design guide](design.md) for the security boundaries before you expose the broker to
other hosts.

## Install the broker

You need SG administrator access to create script accounts, a host reachable from the client
networks that need tokens, and `uv` on the installing operator's path. The service also needs a
system-wide Python 3.11 or later installed outside any home directory. The systemd unit below runs
the broker as an unprivileged dynamic user with `ProtectHome=yes`, which hides `/home` and `/root`
from the service.

From a checkout, install the command as root with that interpreter:

```sh
BROKER_UV=$(command -v uv)
BROKER_PYTHON=/usr/bin/python3.11
sudo env UV_TOOL_DIR=/opt/sg-token-broker/tools UV_TOOL_BIN_DIR=/usr/local/bin \
    "$BROKER_UV" tool install --python "$BROKER_PYTHON" --no-managed-python --no-python-downloads .
```

Set `BROKER_PYTHON` to the interpreter's absolute path on your host. `BROKER_UV` must also be an
absolute path: resolve `uv` before `sudo`, which usually replaces your `PATH`, and if
`command -v uv` prints a relative path, convert it to an absolute one. `--no-managed-python` and
`--no-python-downloads` keep uv from selecting or downloading its own Python, which would live
under a home directory that the service cannot read.

The tool's environment goes under `/opt/sg-token-broker/tools`, and the executable is
`/usr/local/bin/sg-token-broker`, the path the systemd unit uses. Keep both readable and
traversable by other users so that the dynamic service user can run them.

## Create SG script accounts

Each broker scope uses one SG script account (an `ApiUser`). SG enforces that account's permission
role on every token the broker issues for the scope, so give each account only what its scope
needs. For each scope:

1. In SG, go to Admin > Scripts and add a script, for example `broker_read_all`.
2. Assign a permission role that grants only what the scope's name promises. For a read scope,
   clone the lowest-privilege role and remove its create, update, and delete permissions.
3. Record the generated application key. The broker guards this key: anyone who holds it can obtain
   tokens as the script account.
4. If your site supports an API IP allowlist, restrict these script accounts to the broker host's
   egress IP address, so that a leaked key does not work from elsewhere.

A practical starting set has two scopes: `read_all`, backed by `broker_read_all`, for reporting,
dashboards, and farm reads; and `write_production`, backed by `broker_write_production`, for
publishing and ingest tools. Add narrower scopes as needs appear. Each one costs only a script
account and a configuration entry, and a narrower scope limits what a leaked client credential can
reach.

## Create broker clients

Create one broker client per consuming system, not per person: for example `farm_render`,
`pipeline_publish`, and `dailies_ingest`. Separate clients keep audit records attributable and let
you revoke one system without affecting the others. For each client, run:

```sh
sg-token-broker hash-secret
```

Deliver the printed `secret` to the consuming system's secret store, such as the farm's environment
injection or a deployment secret. Put only the printed `hash` in the broker configuration. Always
produce stored hashes with `hash-secret`: configuration validation accepts only the scrypt
parameters, salt length, and digest length that it emits.

Clients send their credentials in an HTTP Basic `Authorization` header, which limits the characters
they can contain. A client ID has 1 to 64 characters from the printable ASCII range 0x21-0x7E,
excluding `:`. A client secret is a non-empty string from the same range. Spaces and non-ASCII
characters are invalid in either.

## Write the configuration

Save the configuration as `/etc/sg-token-broker/broker.yml`, owned by root with mode 0600:

```yaml
site_url: https://your-site.shotgrid.autodesk.com

server:
  bind: 127.0.0.1 # a TLS reverse proxy on the same host forwards here
  port: 8743
  # Without a proxy, bind a LAN address and enable in-process TLS instead:
  # tls:
  #   cert_file: /run/credentials/sg-token-broker.service/tls-cert.pem
  #   key_file: /run/credentials/sg-token-broker.service/tls-key.pem

defaults:
  session_ttl_seconds: 600
  rate_limit_per_minute: 60

scopes:
  read_all:
    script_name: broker_read_all
    script_key_file: /run/credentials/sg-token-broker.service/read_all
  write_production:
    script_name: broker_write_production
    script_key_file: /run/credentials/sg-token-broker.service/write_production

clients:
  farm_render:
    secret_hash: scrypt$16384$8$1$...$...
    scopes: [read_all]
    rate_limit_per_minute: 240
  pipeline_publish:
    secret_hash: scrypt$16384$8$1$...$...
    scopes: [read_all, write_production]
```

Replace each sample `secret_hash` with a value printed by `hash-secret`. The
[configuration reference](#configuration-reference) lists every key and its default.

Create the key files `/etc/sg-token-broker/keys/read_all` and
`/etc/sg-token-broker/keys/write_production`, each containing the matching script account's
application key. Keep them, like `broker.yml`, owned by root with mode 0600: they hold the keys the
broker exists to protect. The configuration refers to the copies that systemd gives the service
under `/run/credentials/sg-token-broker.service/`, described in the next step.

Because those key paths exist only inside the service's credential directory, validate the
configuration through the service: the unit runs `check-config` on its own copy before each start.
`check-config` loads any configured TLS certificate and key as a pair and checks that every script
key resolves.

For in-process TLS, create root-owned, mode 0600 files `/etc/sg-token-broker/tls/cert.pem` and
`/etc/sg-token-broker/tls/key.pem`. Then uncomment the `server.tls` block above and the matching
`LoadCredential` lines in the unit.

## Run the broker with systemd

Save the unit as `/etc/systemd/system/sg-token-broker.service`:

```ini
[Unit]
Description=SG token broker
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/local/bin/sg-token-broker check-config --config /run/credentials/sg-token-broker.service/broker.yml
ExecStart=/usr/local/bin/sg-token-broker serve-app-tokens --config /run/credentials/sg-token-broker.service/broker.yml
Restart=on-failure

# Config and master script keys are root-owned 0600 source files.
# systemd exposes activation-time copies under /run/credentials/sg-token-broker.service/.
LoadCredential=broker.yml:/etc/sg-token-broker/broker.yml
LoadCredential=read_all:/etc/sg-token-broker/keys/read_all
LoadCredential=write_production:/etc/sg-token-broker/keys/write_production
# Enable these only with the in-process TLS fallback in broker.yml.
# LoadCredential=tls-cert.pem:/etc/sg-token-broker/tls/cert.pem
# LoadCredential=tls-key.pem:/etc/sg-token-broker/tls/key.pem

# Hardening
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

`LoadCredential` gives the service private copies of the root-only configuration, key, and TLS
files under `/run/credentials/sg-token-broker.service/`. The unprivileged service user can read
those copies while the source files stay readable only by root. Each credential name must match the
path in `broker.yml`: the `read_all` credential becomes
`/run/credentials/sg-token-broker.service/read_all`, and `tls-cert.pem` and `tls-key.pem` appear in
the same directory. systemd copies credentials when it starts the unit, so restart the service
after changing any source file.

The hardening options limit what a compromised broker process could do. `DynamicUser=yes` runs it
as a temporary unprivileged user. `ProtectSystem=strict` and `ProtectHome=yes` make the file system
read-only and hide home directories. The remaining options give the service a private `/tmp`; block
device access, changes to kernel tunables and control groups, privilege escalation, and writable
executable memory; allow only IPv4 and IPv6 sockets; and restrict system calls to those a typical
service needs. The broker writes no files, so it runs within these limits.

After saving the unit and configuring the TLS proxy and network controls below, start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sg-token-broker
sudo systemctl status sg-token-broker
```

If the service does not start, `systemctl status sg-token-broker` shows the exit status of the
command that failed, and the journal shows its `error:` line. Status 2 means `check-config` or
`serve-app-tokens` rejected the configuration or a script key; correct `broker.yml` or the key
files before restarting. Status 1 means the broker could not start for another reason, such as an
address that is already in use.

The broker writes service messages and audit records at the `INFO` level to standard error, which
systemd sends to the journal. To view the audit records:

```sh
journalctl -u sg-token-broker -o cat | jq -R 'fromjson? | select(.event)'
```

Per-request access lines are logged at `DEBUG`, below the level the command sets, so they do not
appear.

## Restrict network access

The broker's HTTP server comes from Python's standard library. It validates request parsing but is
not designed for direct exposure, so put a reverse proxy, such as nginx or Caddy, in front of it.

Allow inbound connections only from the pipeline VLANs and farm subnets that need tokens. Anyone
who can reach the broker can try client credentials.

Use TLS for all traffic beyond loopback. The recommended layout runs the proxy on the same host and
binds the broker to `127.0.0.1:8743`, so the proxy absorbs connection floods, slow requests, and
protocol edge cases before they reach the broker. If a proxy is impractical, configure in-process
TLS (`server.tls`) and bind a LAN address. That puts the Python listener directly on the network,
so restrict inbound sources as described above.

In-process TLS mode has no failed-authentication limiter. Every well-formed token request runs one
client-secret verification that needs about 16 MiB of memory, whether or not the credentials are
valid, so a flood of failed attempts is bounded only by the 32-request limit below: about 512 MiB
and the host's CPU cores.

The broker refuses to start with plain HTTP on a non-loopback address, and clients refuse
plain-HTTP broker URLs for remote hosts. Remote traffic therefore always uses TLS, at the proxy or
through `server.tls`.

Configure request rates, per-source connection limits, overall connection rates, and slow-client
protection at the proxy, for example with nginx `limit_req` and `limit_conn`. The broker's own
limits are coarse:

- It handles at most 32 requests at once. At capacity, it accepts new connections and closes them
  without a response.
- It closes each connection after one response.
- Its 30-second socket timeout releases fully idle connections. This is not a total request
  deadline and does not stop a client that sends slowly.
- Each client has a per-minute request limit, `rate_limit_per_minute`; requests over the limit
  receive HTTP 429. The limit applies only after the client's secret is verified, so it does not
  slow down floods of failed authentication. Limit those at the proxy.

Monitor `GET /healthz`. It requires no authentication and makes no SG request, so it shows only
that the broker is accepting requests.

If the broker reaches SG through an egress proxy, such as Squid, set the standard proxy variable in
the unit; the broker's HTTP library honors it:

```ini
Environment=HTTPS_PROXY=http://squid:8080
```

If that proxy intercepts TLS, also set
`Environment=REQUESTS_CA_BUNDLE=/etc/sg-token-broker/corp-ca.pem` with your organization's root CA
certificate. Never disable certificate verification on the production broker: its requests to SG
carry the script keys.

## Configure client environments

Each consuming system sets three environment variables, for example injected into each farm job:

```sh
export SG_TOKEN_BROKER_URL='https://sg-broker.studio.internal'
export SG_TOKEN_BROKER_CLIENT_ID='farm_render'
export SG_TOKEN_BROKER_CLIENT_SECRET='value-from-the-secret-store'
```

Python tools use `sg_token_broker.BrokerClient`, which reads these variables or accepts
`broker_url`, `client_id`, and `client_secret` arguments. It caches each scope and token type in
memory and reuses the token until 60 seconds before its `expires_at`, without checking with SG.

Shell tools use `sg-token-broker get-token --scope read_all`, which prints the token as JSON.
`get-token` waits up to 10 seconds for each attempt (`--timeout`) and retries connection failures
and server errors twice (`--retries`). Python callers set the same values with
`BrokerClient(options=ClientOptions(timeout=..., retries=...))`.

## Operations

### Rotate a client secret

Run `hash-secret`, replace the client's `secret_hash` in the configuration, restart the service,
and deliver the new secret to the consuming system. The old secret stops working at the restart.

### Revoke a client

Remove the client's entry from the configuration and restart the service. This stops new issuance
for that client. Tokens it already holds remain subject to SG's lifetime: REST tokens until their
hard expiry, and session tokens for as long as they stay in use. Rotating the script key does not
revoke those sessions; to retire them,
[replace the script account](#retire-a-compromised-script-account).

### Retire a compromised script account

Rotating a script key does not revoke outstanding session tokens. Trashing the script account
suspends them, but restoring the same account can make them usable again. Replace the account so
that the old sessions stay invalid:

1. Regenerate the application key. This stops anyone from minting new tokens with the leaked key.
2. Rename the script, for example from `broker_read_all` to `broker_read_all-retired-YYYYMMDD`.
3. Trash it and leave it trashed. Its sessions stay suspended only while it remains trashed.
4. Create a new script with the original name and a fresh key.
5. Update the broker's source key file and restart the service.

The restart loads the new key and clears the broker's token cache. It does not clear tokens cached
by running `BrokerClient` objects or held by open SG connections (`shotgun_api3.Shotgun` objects).
For immediate recovery, recreate both in each affected process. Otherwise, wait until each
`BrokerClient` fetches a new token, which happens 60 seconds before its cached token's
`expires_at`, then recreate the affected SG connections.

Reusing the script name keeps configuration references valid; it does not preserve or replace
outstanding sessions. To rehearse this procedure with a disposable account, use the
[revocation check](#verify-revocation-behavior-on-a-trial-site).

### Rotate a script key routinely

Routine rotation limits how long a silently leaked key stays useful. Regenerate the key in SG,
update the source key file, and restart the service. Until the restart, requests that the broker
cannot answer from its cache fail with HTTP 502, because the broker still holds the old key.
Rotation does not revoke outstanding sessions; use the
[account replacement procedure](#retire-a-compromised-script-account) for that.

### Match the session cache to SG's session expiry

For session tokens, the broker's `expires_at` is advisory: it marks when the broker stops reusing
its cached session, `defaults.session_ttl_seconds` after minting. Find your site's session expiry
in its site preferences or from Autodesk support, and set `defaults.session_ttl_seconds`
comfortably below it. Otherwise the broker could keep handing out a cached session that SG has
already expired for inactivity. SG's expiry is a sliding inactivity window, so a session token in
active use never ages out on its own.

## Audit logs

The broker writes every issuance, denial, and error as one JSON line. Records never contain token
values or secrets. `token_fp` identifies a token by the first 16 hexadecimal characters of its
SHA-256 digest.

| Event                                     | Fields                                                                                                               |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Issue (`issue`)                           | `ts`, `event`, `client_id`, `scope`, `token_type`, `token_fp`, `cache`, `source_ip`, `request_id`                    |
| Request denial or error (`deny`, `error`) | `ts`, `event`, `client_id`, `scope`, `token_type`, `reason`, `source_ip`, `request_id`; `detail` for upstream errors |
| Pre-service denial (`deny`)               | `ts`, `event`, `reason`, `source_ip`, `request_id`                                                                   |
| Unhandled error (`error`)                 | `ts`, `event`, `reason`, `detail`, `source_ip`, `request_id`                                                         |

- `cache` is `hit` when the broker reused a cached token and `miss` when it minted a new one.
- `reason` comes from a fixed set and never contains caller-supplied text: `missing_authorization`,
  `malformed_authorization`, `invalid_client`, `rate_limited`, `forbidden`, `bad_request`,
  `not_found`, `method_not_allowed`, `upstream_error`, or `internal_error`.
- A caller-supplied `client_id` longer than 64 characters is truncated and marked with
  `client_id_truncated`. An unrecognized `scope` or `token_type` is recorded as `invalid`.
- `detail` appears on upstream errors, where it briefly describes the SG failure, and on unhandled
  errors, where it names only the exception class.
- `source_ip` is the address of the peer connected to the broker. The broker does not read
  `X-Forwarded-For`, so behind a reverse proxy every record shows the proxy's address: `127.0.0.1`
  in the recommended same-host layout. Keep the proxy's access log; it records each request's
  original client address. The user-token service differs: it records forwarded addresses from the
  proxies listed in `SGUT_TRUSTED_PROXIES` (see
  [private deployment](user-token-service.md#private-deployment-for-session-tokens)).

To trace a found token to its issuance, compute its fingerprint and search the journal for it:

```sh
printf '%s' "$FOUND_TOKEN" | sha256sum | cut -c1-16
```

The broker caches tokens per client, so the matching `issue` records name the one client that
received the token.

## Verify revocation behavior on a trial site

This optional check shows how your SG site treats an outstanding session token when its script
account's key is rotated and the account is trashed and restored. Run it after material SG
authentication changes. It changes a real script account, so run it as an SG administrator with a
dedicated disposable script on a trial site, never with a production account.

```sh
export SGTB_VERIFY_KEY='disposable-script-application-key'
sg-token-broker verify-revocation \
    --site-url https://yourtrial.shotgrid.autodesk.com \
    --script-name disposable_revocation_test \
    --script-key-env SGTB_VERIFY_KEY
```

Without `--script-key-env`, the command prompts for the key without echoing it.

The command mints a session token, reports the site's REST token lifetime, and then asks you to
make each change in SG, testing the token after each one: rotating the key, trashing the script,
restoring it, and optionally the rename-and-replace procedure from
[Retire a compromised script account](#retire-a-compromised-script-account). When a change retires
the token, the output names that retirement procedure. At the end, it reminds you to restore the
script account unless you intend to leave it retired. Save the result in your operational records.

| Exit code | Meaning                                                                    |
| --------- | -------------------------------------------------------------------------- |
| 0         | A procedure retired the token immediately; the output names it.            |
| 1         | The token survived every step tried.                                       |
| 2         | A setup or SG error made the run inconclusive.                             |
| 3         | The run ended on an unverified step, such as a skipped rename-and-replace. |

If the token survives both key rotation and ApiUser disable, the command exits 1 and advises you to
reassess issuing app-token session tokens on this site, since a leaked one can only age out through
SG's sliding session expiry. Exit code 1 after rename-and-replace reports survival without that
advice.

If the trial site is reached through an egress proxy, add `--proxy`; the `HTTP_PROXY` and
`HTTPS_PROXY` environment variables also work. If the proxy intercepts TLS, the command reports
`error: could not mint a session token: ... SSLError` on stderr with corporate CA guidance on the
same line. Pass that CA certificate with `--ca-bundle`, or set `REQUESTS_CA_BUNDLE`. Your network
administrators can provide the certificate, or you can export it from a browser on the same
machine. `--insecure` skips certificate verification for this one-shot test; use it only with a
disposable key, and never on the production broker.

For machines without the package installed, `scripts/verify_sg_revocation.py` in the repository is
a standalone, single-file copy of this check. It needs only Python 3.11 or later and `requests`,
and accepts the same options and exit codes.

## Configuration reference

`broker.yml` is a YAML mapping with the keys below. It must define at least one scope and one
client. Integer values must be plain YAML integers, because quoted numbers and booleans such as
`yes` are rejected, and durations and rate limits must be positive.

| Key                                  | Default                          | Description                                                                                         |
| ------------------------------------ | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `site_url`                           | Required                         | SG site URL. It must use HTTPS; plain HTTP is accepted only for a loopback host.                    |
| `server.bind`                        | `127.0.0.1`                      | Address to listen on. Any non-loopback address requires `server.tls`.                               |
| `server.port`                        | `8743`                           | TCP port to listen on.                                                                              |
| `server.tls.cert_file`               | None                             | Certificate file for in-process TLS. Set it together with `key_file`.                               |
| `server.tls.key_file`                | None                             | Private-key file for in-process TLS.                                                                |
| `defaults.session_ttl_seconds`       | `600`                            | How long the broker reuses a cached session token, and the session `expires_at` it reports.         |
| `defaults.rate_limit_per_minute`     | `60`                             | Default per-client request limit for each minute.                                                   |
| `scopes.<name>.script_name`          | Required                         | SG script account name for the scope.                                                               |
| `scopes.<name>.script_key_file`      | One of two                       | File containing the script account's application key; surrounding whitespace is ignored.            |
| `scopes.<name>.script_key_env`       | One of two                       | Environment variable containing the key. Set exactly one of `script_key_file` and `script_key_env`. |
| `clients.<id>.secret_hash`           | Required                         | Hash printed by `hash-secret`.                                                                      |
| `clients.<id>.scopes`                | Required                         | Non-empty list of configured scope names that the client may request.                               |
| `clients.<id>.rate_limit_per_minute` | `defaults.rate_limit_per_minute` | Request limit for this client for each minute.                                                      |

## HTTP API reference

The broker serves two routes. Routing uses only the request path, so a query string does not change
the route.

`POST /v1/token` issues a token. Send the client ID and secret with HTTP Basic authentication and a
JSON object body of at most 8192 bytes:

```json
{
  "scope": "read_all",
  "token_type": "session"
}
```

`token_type` is `session`, the default, or `rest`. A successful response contains `token`,
`token_type`, `scope`, `site_url`, and `expires_at`, an ISO 8601 timestamp with a time zone.

`GET /healthz` answers `{"status": "ok"}` without authentication or an SG request.

Error responses are JSON objects with `error` and `detail` fields:

| Status | `error`              | Meaning                                                                     |
| ------ | -------------------- | --------------------------------------------------------------------------- |
| 400    | `bad_request`        | Malformed request or body, an unknown `token_type`, or a body sent with GET |
| 401    | `invalid_client`     | Missing, malformed, unknown, or wrong client credentials                    |
| 403    | `forbidden`          | The client may not use the requested scope                                  |
| 404    | `not_found`          | Unknown path                                                                |
| 405    | `method_not_allowed` | Unsupported method for the path                                             |
| 413    | `payload_too_large`  | Body larger than 8192 bytes                                                 |
| 429    | `rate_limited`       | The client exceeded its per-minute limit                                    |
| 500    | `internal_error`     | Unexpected error, or a script key the broker cannot read                    |
| 502    | `upstream_error`     | SG rejected or failed the token request                                     |

`BrokerClient` and `get-token` retry server errors and connection failures; other errors fail
immediately with the response's `detail`.
