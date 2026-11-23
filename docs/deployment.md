# App-token broker deployment

This guide is for operators who run the app-token broker for shared use. The broker issues SG
tokens for configured script accounts to the farm jobs, pipeline services, and tools you register
as clients. The steps use Linux, systemd, and a TLS reverse proxy. For a first run on your own
machine, use the [quick start](../README.md#quick-start); for tokens that carry a person's own SG
permissions, use the [user-token service guide](user-token-service.md).

For a farm, see [Capacity and multiple broker processes](#capacity-and-multiple-broker-processes).
After setup, use [Operations](#operations) for credential changes and [Audit logs](#audit-logs) to
investigate requests. Look up individual settings and responses in the
[configuration](#configuration-reference) and [HTTP API](#http-api-reference) references.

Read the [security boundaries](design.md) before exposing the broker to other hosts.

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

The configuration below uses two scopes:

| Scope              | Script account            | Typical use                           |
| ------------------ | ------------------------- | ------------------------------------- |
| `read_all`         | `broker_read_all`         | Reporting, dashboards, and farm reads |
| `write_production` | `broker_write_production` | Publishing and ingest                 |

Add narrower scopes as needed. Each requires a script account and a configuration entry, and limits
what a leaked client credential can reach.

## Create broker clients

Create one broker client per consuming system, not per person: for example `farm_render`,
`pipeline_publish`, and `dailies_ingest`. Separate clients keep audit records attributable and let
you revoke one system without affecting the others. For each client, run:

```sh
sg-token-broker hash-secret
```

Deliver the printed `secret` to the hosts that run the consuming system, for example as a
root-owned file placed by configuration management or through the service manager's credential
mechanism. Do not commit it to source control or put it in job-level settings, such as job
environment variables that a render scheduler shows to its users. Any process on those hosts that
can read the secret can use it, including jobs that other people submit. Put only the printed
`hash` in the broker configuration. Use `hash-secret` for every stored hash; other hash formats are
rejected. See [Client credentials](#client-credentials) for the accepted ID and secret characters.

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
  dailies_ingest:
    secret_hash: scrypt$16384$8$1$...$...
    scopes: [read_all]
    token_types: [rest]
```

Replace each sample `secret_hash` with a value printed by `hash-secret`. The
[configuration reference](#configuration-reference) lists every key and its default.

Set `token_types: [rest]` for a client whose tools do not use `shotgun_api3`, as for
`dailies_ingest` above. Its secret then cannot obtain session tokens, which stay usable for as long
as someone keeps using them. Clients without `token_types` may request both types.

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
SuccessExitStatus=130 143

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

The hardening options run the broker as a temporary unprivileged user, make the file system
read-only, hide home directories, and isolate temporary files. They also restrict devices, kernel
and control-group changes, privilege escalation, writable executable memory, sockets, and system
calls. The broker writes no files, so it runs within these limits.

On stop or restart, systemd sends SIGTERM and the broker exits immediately. `SuccessExitStatus`
makes systemd treat the broker's SIGINT and SIGTERM exit codes as clean stops. For a planned
restart behind nginx, follow the [rolling restart steps](#configure-the-reverse-proxy) to take the
broker out of rotation first.

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

### Put TLS and access controls in front of the broker

The broker's HTTP server comes from Python's standard library. It validates request parsing but is
not designed for direct exposure, so put a reverse proxy, such as nginx or Caddy, in front of it.

Allow inbound connections only from the pipeline VLANs and farm subnets that need tokens. Anyone
who can reach the broker can try client credentials. This restriction is also what limits a leaked
client secret, which works only from hosts that can reach the broker. It does not limit issued SG
tokens, which work wherever SG accepts them.

Use TLS for all traffic beyond loopback. The recommended layout runs the proxy on the same host and
binds the broker to `127.0.0.1:8743`, so the proxy absorbs connection floods, slow requests, and
protocol edge cases before they reach the broker. If a proxy is impractical, configure in-process
TLS (`server.tls`) and bind a LAN address. That puts the Python listener directly on the network,
so restrict inbound sources as described above.

The broker refuses to start with plain HTTP on a non-loopback address, and clients refuse
plain-HTTP broker URLs for remote hosts. Remote traffic therefore always uses TLS, at the proxy or
through `server.tls`.

### Configure the reverse proxy

Use the [standalone nginx configuration](reverse-proxy.conf) as a starting point. Set the
`server_name`, install the TLS certificate chain and private key at the configured paths, and
restrict inbound traffic to your client networks. Test the installed configuration with `nginx -t`
before reloading nginx. The proxy forwards to the broker over loopback.

For a large farm, use an ECDSA P-256 server certificate if all clients support it. It reduced nginx
CPU time for a burst of new TLS connections in the farm benchmark. Set `worker_processes` to the
number of CPUs dedicated to nginx, or to the shared service CPU set when nginx runs alongside the
brokers. The example uses four shared CPUs. In the benchmark VM, `auto` started ten nginx workers
even though the service had four CPUs.

The TLS listener requests a backlog of 4096. On Linux, run `sysctl net.core.somaxconn` in the
proxy's network namespace. Set it to at least 4096 or the kernel silently shortens the queue. Check
listen drops and SYN retransmissions during a cold start.

Set the client-facing idle timeout on every proxy or load balancer above the longest scheduled
retry interval. With the broker's maximum `Retry-After` of 60 seconds, a cold acquisition can wait
64 seconds (up to four seconds of jitter). A client renewing a cached key can wait 110 seconds (up
to 50 seconds of jitter). Allow at least 120 seconds for this deployment. If a front end sends a
larger `Retry-After`, allow that delay plus 50 seconds and a margin. An idle connection closed as
the client starts its next request can cause a transport error.

Count idle TLS connections when sizing nginx. For each worker, budget the maximum concurrent client
connections divided by the number of workers, multiplied by the observed peak-to-average imbalance.
Add the peak upstream connections on that worker and headroom for listeners and variation. For
example, the four-worker benchmark reached 10,000 live client connections. In run 377, the busiest
worker held 2,851, about 1.14 times the full-farm average. Budgeting for a 1.2-fold imbalance
requires 3,000 client slots on the busiest worker before upstream connections. Set
`worker_connections` to cover that total. Set the nginx service's open-file limit above it to allow
for logs and other files. If using `worker_rlimit_nofile`, the service's hard file limit must
permit that setting. For the reference's 4,096 connection slots, a systemd override such as
`LimitNOFILE=8192` leaves descriptors available for other files. Check the effective limit in
`/proc/<worker-pid>/limits` and measure the busiest worker under load. With 768 connections per
broker, the largest sum of a worker's measured peak client connections and estimated peak upstream
connections was 3,206. The two peaks can occur at different times.

The example limits each source address to 20 requests per second, with room to delay 20 excess
requests, and 32 concurrent requests. Across the listener it admits 2,000 requests per second with
room for 4,096 excess requests. This example uses four active broker processes. For two brokers,
set the farm zone to `rate=1000r/s` and set `max_conns=1024` on each active upstream. This keeps
room for 2,048 upstream connections in total. At 512 per broker, one of two 10,000-machine runs
produced 502 responses. Both repeats at 1,024 completed with only busy and rate-limit retries.
Check the busiest interval in the nginx error log for `no live upstreams` and measure acquisition
latency before raising the rate. Rate-limit overflow gets HTTP 429. Size per-source limits for the
addresses nginx sees, especially if many machines share a NAT address. These limits apply before
the broker checks credentials.

nginx buffers request bodies, limits them to 8192 bytes, and sets timeouts for slow headers, bodies
and responses. The four-broker reference allows 768 connections per upstream across nginx workers,
or 3,072 upstream connections in total. If every upstream is at its limit, nginx can return HTTP
502\. If a connection fails before nginx sends a token POST, nginx can try one other broker. The
example allows two tries in total and three seconds in which to start the second try. Once nginx
sends the POST, the client owns any retry. Leave `non_idempotent` out of `proxy_next_upstream` so a
lost reply cannot make nginx replay a mint or verification. Broker error responses and
`Retry-After` pass through to the caller.
[nginx proxy retry rules](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream)

Each loopback peer uses `max_fails=0`. During a burst, nginx can reach its connect timeout on
several live brokers at once. Disabling passive failure marking keeps all of them eligible as soon
as connections become available. For a planned rolling restart, remove one broker from rotation and
reload nginx. Confirm that the same master started the new worker generation. Before stopping the
broker, verify that every worker serving the old configuration has exited. Inspect all workers
under that master, including any marked `worker process is shutting down`. A replacement worker
started just before the reload can still drain queued requests using the old configuration. Once
the old generation has exited, restart the broker, check its health, and return it to rotation
before moving on. [nginx reload lifecycle](https://nginx.org/en/docs/control.html#reconfiguration)

The broker exits immediately on SIGTERM (status 143) or SIGINT (status 130). This cuts off any
requests still in flight. Clients retry interrupted requests under their normal retry policy.

The shipped image runs tini as PID 1 so it can forward a stop signal even while Python is starting.
To select the app broker in that image, use `--entrypoint tini` and pass
`-- sg-token-broker serve-app-tokens --config /path/to/broker.yml` after the image name. If you
build your own image, run the broker under tini or dumb-init, or start it with `docker run --init`.

### Capacity and multiple broker processes

Size the deployment by how many distinct combinations of client, scope and token type need a new SG
token at once. On one process, a thousand jobs requesting the same token can share one SG mint. A
thousand different combinations may each need their own. Each process uses these defaults:

| Resource                                                                     | What happens at the limit                                                                                                                                                                                                 |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Listen backlog of 1024                                                       | The OS can cap the backlog. If it refuses the requested size, the broker retries with 5.                                                                                                                                  |
| 32 request workers                                                           | A full listener tries to send 503 `server_busy` with `Retry-After: 1` and closes the connection. If it cannot send immediately, including before an in-process TLS handshake, it just closes.                             |
| 24 workers doing or waiting for SG work, or waiting for another secret check | Further requests that need to join this work get 503. The remaining workers can still serve cache hits, verify credentials, or reject requests.                                                                           |
| 2 concurrent secret verifications                                            | Requests presenting the same client and secret share a check. If a different check needs a slot and all are busy, it gets 503. A successful match is remembered for 600 seconds using a keyed digest.                     |
| 8 concurrent SG calls                                                        | An additional mint gets 503 `server_busy` with `Retry-After: 1`.                                                                                                                                                          |
| 60 SG token requests per client per minute                                   | `rate_limit_per_minute` charges each actual SG mint, successful or failed. The fixed 60-second window starts with its first charged request. Once spent, 429 `rate_limited` includes `Retry-After` until the window ends. |

An uncached secret check uses about 16 MiB per active scrypt computation. Expiry of a remembered
match requires another check. The broker has no per-client failed-login lockout, so keep per-source
limits at the proxy.

Budget CPU for cold credentials separately from SG mint capacity. Count each credential once for
every broker process that must verify it. Multiply that count by the CPU-seconds for one
verification on your hardware, then divide by the CPU cores available to the brokers. This
estimates the time needed for verification alone. During rotation, a verification can require more
than one scrypt computation. In the four-process farm benchmark, 100 cold credentials required 400
computations averaging 0.078 CPU-seconds each, or 31.2 CPU-seconds in all. Two cores would need
about 15.6 seconds for that work before allowing for HTTP and mint processing.

When many distinct credentials arrive together, allow one broker CPU core per concurrently running
verification and give the TLS proxy its own CPU capacity. Two verification slots per process allow
up to eight independent checks across the four-broker reference. The four-core benchmark served
overload through retries. For a farm where all eight checks must execute in parallel, budget eight
broker cores plus proxy capacity. On Linux, separate service CPU sets can reserve cores for nginx,
or a service manager can assign it a higher CPU weight where cgroup delegation is available. Check
the resulting broker queue and the proxy's runnable wait together. Reserving too much of a small
CPU budget for the proxy can exhaust the upstream connections while brokers are still working.

The mint budget covers all scopes, token types and credentials for that client. Cache hits,
requests that join a mint, capacity refusals, and failures served from memory spend none of it. The
broker closes each connection after one response. Its 30-second socket timeout releases idle
connections.

After SG becomes unavailable, the broker holds off for 5 seconds for that client, scope and token
type. During that interval, 503 `upstream_unavailable` gives the remaining wait in `Retry-After`.
After an SG refusal or unusable response, the broker repeats the same 502 for 30 seconds. After
either interval, the next admitted request tries SG again, subject to the client's mint budget.
Restarting the broker clears the remembered failures.

The reference farm runs four broker processes on loopback ports 8743 through 8746, behind one nginx
listener. Install them on the same host within the four-CPU, 8 GiB service budget used for the
benchmark. All three 10,000-machine one-minute bursts passed on that budget, while the test host
could not deliver all 10,000 first sends within one second. Apply those limits to the proxy and
brokers together. For example, put the services in one systemd slice with `CPUQuota=400%` and
`MemoryMax=8G`. For a single-process deployment, keep only port 8743 in the upstream. To add the
second instance to the systemd service above:

1. Copy `broker.yml` to `/etc/sg-token-broker/broker-2.yml` with the same root ownership and mode
   `0600`. Set `server.port` to `8744`. In each credential path, change the directory to
   `/run/credentials/sg-token-broker-2.service/`.
2. Copy the unit to `/etc/systemd/system/sg-token-broker-2.service`. Use that same credential
   directory for `ExecStartPre` and `ExecStart`. Set
   `LoadCredential=broker.yml:/etc/sg-token-broker/broker-2.yml`. Both units can load the same
   root-owned script key files.
3. Run `sudo systemctl daemon-reload` and `sudo systemctl enable --now sg-token-broker-2`. Check
   `/healthz` on both loopback ports, then repeat for instances 3 and 4 on ports 8745 and 8746.
   Check each listener before reloading the nginx configuration.

Keep client, scope and key configuration consistent. Each process has its own cache, authentication
memory, SG slots and per-client budgets. Adding a process adds capacity and can also multiply both
SG calls and the client's effective allowance. A retry can reach a different process.
[Recovery from a rejected token](sg-token-behavior.md#replacing-a-rejected-app-token) is guaranteed
with up to eight broker processes behind one proxy.

### Check health and configure SG egress

Monitor `GET /healthz`. It requires no authentication and makes no SG request, so it shows only
that the broker is accepting requests.

If the broker reaches SG through an egress proxy, such as Squid, set the standard proxy variable in
the unit; the broker's HTTP library honors it:

```ini
Environment=HTTPS_PROXY=http://proxy.example:3128
```

If that proxy intercepts TLS, also set
`Environment=REQUESTS_CA_BUNDLE=/etc/sg-token-broker/corp-ca.pem` with your organization's root CA
certificate. Never disable certificate verification on the production broker: its requests to SG
carry the script keys.

## Configure client environments

Each consuming system sets three environment variables in the processes that request tokens, for
example from a root-owned file that the worker service on each host loads:

```sh
export SG_TOKEN_BROKER_URL='https://broker.example.invalid'
export SG_TOKEN_BROKER_CLIENT_ID='farm_render'
export SG_TOKEN_BROKER_CLIENT_SECRET='value-from-the-secret-store'
```

Python tools use `BrokerClient()`, which reads those variables or accepts `broker_url`,
`client_id`, and `client_secret`. Keep an instance for the life of the process. Shell tools use
`sg-token-broker get-token --scope read_all`, which prints the token as JSON. For existing
`shotgun_api3` tools, see [Replacing script keys in existing code](migrating.md).

### Client tuning and retries

Both `BrokerClient` and `UserTokenClient` take these keyword-only settings, for example
`BrokerClient(timeout=10, retries=0)`. Invalid tuning values raise `ValueError`. Spell out CLI
option names in full, and look for a suggested spelling if an option is unrecognized.

| Python keyword   | CLI option on both fetch commands | Default         | Meaning                                                                                         |
| ---------------- | --------------------------------- | --------------- | ----------------------------------------------------------------------------------------------- |
| `timeout`        | `--timeout`                       | 10 seconds      | Positive finite time to connect and for each wait for response data.                            |
| `retries`        | `--retries`                       | `None` (no cap) | Nonnegative integer count of additional requests. Zero allows one request.                      |
| `refresh_margin` | Python only                       | 60 seconds      | Nonnegative finite lead time for proactive renewal. User sessions renew only on forced refresh. |
| `max_wait`       | `--max-wait`                      | 300 seconds     | Positive finite budget for starting requests in one fetch.                                      |

Configure the final service URL directly. Both clients stop at HTTP redirects and report the
destination origin when available. If a REST token expires before delivery, the client seeks a
usable token within the same request and time limits.

When a fetch needs the service, both clients retry connection failures, HTTP 429 and 5xx responses.
Two 5xx codes end the call immediately: `sg_rejected` and `sg_invalid_response`. A 4xx other than
429 also ends the call. A temporary failure from a proxy, including 502 or 504, is retryable. Cold
retries spread randomly over a window starting at 0.5 seconds and doubling to 4 seconds. A valid
`Retry-After` in seconds or as an HTTP date adds a minimum delay before that spread. A past date
contributes zero and a malformed value is ignored.

Each fetch has its own `max_wait` budget. For app tokens it starts when the call begins, including
time spent waiting for another caller or an earlier retry delay. For user tokens it starts after
identity resolution. A request started within budget can finish later and succeed. If the next
permitted start falls outside the budget, the client fails immediately. For example,
`next request permitted in 60s, beyond max_wait 5s` can include `(Retry-After from the broker)` or
`(Retry-After from the service)` when the header set the delay. Other stopping messages include
`max_wait 300s exhausted` and `no token after 1 attempt(s) (retries=0)`. When available, the
message ends with `; last failure: ...` to identify what failed.

### How an app client renews

A `BrokerClient` caches each scope and token type independently. The next call renews when the
token reaches its refresh time, spread over the minute before the refresh margin (60 to 120 seconds
before `expires_at` by default, or immediately if already due). Concurrent fetches for the same key
share a request in flight. Other keys can proceed independently.

If renewal encounters a retryable failure, the client immediately returns a usable cached token. A
session can still work past its advisory `expires_at` while SG keeps it active. A REST token can be
used only before `expires_at`. The client never falls back to a token it remembers as rejected.
Report an SG rejection with
[the token that failed](sg-token-behavior.md#replacing-a-rejected-app-token).

If the broker returns the same token and deadline, or renewal encounters a retryable failure, the
client schedules the next request for that key 10 to 60 seconds later. A valid `Retry-After` on a
retryable failure sets the minimum delay, with up to 50 seconds added at random. If a REST token
expires before then, the caller waits only if another request can start within its budget.

A terminal renewal failure such as 502 `sg_rejected` raises `BrokerClientError` immediately. The
next fetch may contact the broker again. Each broker process remembers that SG refusal for 30
seconds and can answer repeated requests during that interval without calling SG again.

## Operations

### Rotate a client secret

During a planned rotation, both credentials share the client ID, scopes, token types, cached tokens
and mint allowance.

1. Run `sg-token-broker hash-secret`. Replace the client's `secret_hash` with a `secret_hashes`
   list containing the old and new hashes. Validate and restart every broker with both hashes
   before changing consumers. Roll one process at a time behind the proxy. With one process,
   callers holding tokens can keep using them during the restart. New acquisitions retry within
   `max_wait` and any explicit retry cap. With `retries=0`, a failed request ends the call.
2. Distribute the new secret to every consuming group. Restart long-running jobs or recreate their
   clients with the new secret. A running `BrokerClient` retains the secret it was given.
3. Confirm adoption on each group's hosts. For example, run
   `sg-token-broker get-token --scope read_all > /dev/null` with the new credential and an allowed
   scope. Match an `issue` event to the new [credential ID](#audit-logs). Quiet logs cannot confirm
   adoption because jobs using existing sessions make no acquisition requests.
4. Remove the old hash and roll the processes again. Until this step, consumers can roll back to
   the old secret.

**Emergency replacement.** If the old secret has leaked, skip the overlap. Run `hash-secret`,
configure only the new `secret_hash`, and restart or withdraw every process that accepts the old
secret. Deliver the new secret and restart consumers. Acquisitions with the leaked secret stop once
the last old process is out of service. Verify that each peer denies the old secret as described
under [Revoke a client](#revoke-a-client). Previously issued SG tokens retain their SG lifetimes.

### Revoke a client

If this is the last client, stop or withdraw every peer. A broker requires at least one configured
client. To resume service, configure an authorized replacement client on every peer, then restart
and verify the retired credential as described below. If no replacement is authorized, keep the
fleet stopped or withdrawn and verify that callers cannot reach any issuer.

1. Remove the client's entry from every serving peer's configuration. For emergency revocation,
   stop each peer or block access to it until it has loaded the change. In the four-process
   reference this includes the original systemd service and instances 2 through 4.
2. Restart each unit with its updated configuration. From the broker host, target each peer's
   loopback port directly (8743 through 8746 in the reference). Use the revoked credential with
   `sg-token-broker get-token --scope SCOPE --retries 0 > /dev/null` for a previously allowed
   scope. Set `SG_TOKEN_BROKER_URL` to the peer under test and confirm HTTP 401. Keep unverified
   peers withdrawn, including any peer that returns a token. Declare revocation complete after
   confirming denial on every peer.

Previously issued REST tokens retain their SG lifetime. Session tokens can stay valid as long as
they remain in use. To retire those sessions,
[replace the script account](#retire-a-compromised-script-account).

### Retire a compromised script account

Rotating a script key does not revoke outstanding session tokens. Trashing the script account
suspends them, but restoring the same account can make them usable again. Replace the account so
that the old sessions stay invalid:

1. Regenerate the application key. This stops anyone from minting new tokens with the leaked key.
2. Rename the script, for example from `broker_read_all` to `broker_read_all-retired-YYYYMMDD`.
3. Trash it and leave it trashed. Its sessions stay suspended only while it remains trashed.
4. Create a new script with the original name and a fresh key.
5. Update the source key file for every serving peer. Restart each broker unit to load the new
   credential and clear its token cache. Verify a fresh issuance for the affected scope directly on
   each restarted peer before returning it to service.

Running `BrokerClient` objects and open SG connections (`shotgun_api3.Shotgun` objects) still hold
their own tokens. If SG rejects a session held by a running job, report it and rebuild the
connection using the
[app-token recovery procedure](sg-token-behavior.md#replacing-a-rejected-app-token).

Reusing the script name keeps configuration references valid; it does not preserve or replace
outstanding sessions. To rehearse this procedure with a disposable account, use the
[revocation check](#verify-revocation-behavior-on-a-trial-site).

### Rotate a script key routinely

Regenerate the key in SG and update the source key file used by each peer. Restart every systemd
unit that loads the key, including all four units in the reference farm. Each unit takes its own
`LoadCredential` copy at startup, even when all units share `/etc/sg-token-broker/keys/read_all`.
Check a fresh issuance for the affected scope directly on each restarted peer.

For deployments that read a key file directly, the broker rereads it at each mint, so replacing
each peer's file takes effect at its next mint. Restart every process that receives the key through
its environment. While SG rejects the old key, requests that need a fresh token fail with HTTP 502.

Routine rotation limits how long a leaked key can mint tokens. It does not revoke outstanding
sessions; use the [account replacement procedure](#retire-a-compromised-script-account) for that.

### Match the session cache to SG's session expiry

For session tokens, the broker's `expires_at` is advisory: it marks when the broker stops reusing
its cached session, `defaults.session_ttl_seconds` after minting. Find your site's session expiry
in its site preferences or from Autodesk support, and set `defaults.session_ttl_seconds`
comfortably below it. Otherwise the broker could keep handing out a cached session that SG has
already expired for inactivity. SG's expiry is a sliding inactivity window, so a session token in
active use never ages out on its own.

## Audit logs

For each issuance, denial or error, the broker attempts to write and flush a JSON audit line before
sending the first byte of the final response. This includes HTTP parser rejections. Successful
health checks, interim `100 Continue` responses and listener-level `server_busy` refusals have no
audit event. The log destination determines whether the record is retained.

Records never contain token values or secrets. `token_fp` identifies a token by the first 16
hexadecimal characters of its SHA-256 digest.

| Event                                     | Fields                                                                                                                                                     |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Issue (`issue`)                           | `ts`, `event`, `client_id`, `credential`, `scope`, `token_type`, `token_fp`, `cache`, `outcome`, `source_ip`, `request_id`, and `replaced` on replacement  |
| Request denial or error (`deny`, `error`) | `ts`, `event`, `client_id`, `scope`, `token_type`, `reason`, `source_ip`, `request_id`, plus `credential` after authentication and `detail` when available |
| Pre-service denial (`deny`)               | `ts`, `event`, `reason`, `source_ip`, `request_id`                                                                                                         |
| Unhandled error (`error`)                 | `ts`, `event`, `reason`, `detail`, `source_ip`, `request_id`                                                                                               |

- During rotation, use `credential` to see which secret authenticated a request. Its value is the
  first 12 hex characters of SHA-256 of the stored hash string (without a trailing newline). Every
  issue event and every handled denial or error after authentication includes this ID. An
  unexpected exception that returns 500 `internal_error` produces an unattributed audit event with
  neither `client_id` nor `credential`.
- On issuance, `outcome` is `hit`, `joined`, `minted`, or `replaced`. The first two have
  `cache: hit` and the others have `cache: miss`. An issue that replaced a reported token also has
  `replaced: true`.
- `reason` identifies the denial or failure. Service errors use the codes in the
  [HTTP reference](#http-api-reference). Pre-service reasons include `missing_authorization` and
  `malformed_authorization`. A connection refused before a worker starts has no request event.
- A caller-supplied `client_id` longer than 64 characters is truncated and marked with
  `client_id_truncated`. An unrecognized `scope` or `token_type` is recorded as `invalid`.
- For an SG refusal, `detail` gives the operation and HTTP status. Recognized RPC codes and local
  repair hints distinguish script authentication, missing permission and target-user issues. The
  broker omits SG response text from diagnostics. Key-loading failures name the variable or file.
  Unhandled errors name the exception class.
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

The broker caches tokens per client, so matching `issue` records name the client for which it
issued the token. An interrupted connection can leave an audit record before the client receives
the response.

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
client. Any other key is an error, so a misspelled key such as `token_type` fails `check-config`
instead of being ignored. Integer values must be plain YAML integers, because quoted numbers and
booleans such as `yes` are rejected, and durations and rate limits must be positive.

| Key                                  | Default                          | Description                                                                                         |
| ------------------------------------ | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `site_url`                           | Required                         | SG site URL without embedded credentials. Use HTTPS, or HTTP on a loopback host.                    |
| `server.bind`                        | `127.0.0.1`                      | Address to listen on. Any non-loopback address requires `server.tls`.                               |
| `server.port`                        | `8743`                           | TCP port to listen on.                                                                              |
| `server.tls.cert_file`               | None                             | Certificate file for in-process TLS. Set it together with `key_file`.                               |
| `server.tls.key_file`                | None                             | Private-key file for in-process TLS.                                                                |
| `defaults.session_ttl_seconds`       | `600`                            | How long the broker reuses a cached session token, and the session `expires_at` it reports.         |
| `defaults.rate_limit_per_minute`     | `60`                             | SG token requests per client per fixed 60-second window, per process.                               |
| `defaults.token_types`               | `[session, rest]`                | Default token types that each client may request.                                                   |
| `scopes.<name>.script_name`          | Required                         | SG script account name for the scope.                                                               |
| `scopes.<name>.script_key_file`      | One of two                       | File containing the script account's application key; surrounding whitespace is ignored.            |
| `scopes.<name>.script_key_env`       | One of two                       | Environment variable containing the key. Set exactly one of `script_key_file` and `script_key_env`. |
| `clients.<id>.secret_hash`           | One of two                       | One hash printed by `hash-secret`.                                                                  |
| `clients.<id>.secret_hashes`         | One of two                       | List of one or two distinct stored hashes. Use exactly one of `secret_hash` and `secret_hashes`.    |
| `clients.<id>.scopes`                | Required                         | Non-empty list of configured scope names that the client may request.                               |
| `clients.<id>.rate_limit_per_minute` | `defaults.rate_limit_per_minute` | SG token requests allowed for this client per window on each process.                               |
| `clients.<id>.token_types`           | `defaults.token_types`           | Non-empty list of the token types, `session` and `rest`, that the client may request.               |

### Client credentials

Clients send their credentials in an HTTP Basic `Authorization` header, which limits the characters
they can contain. A client ID has 1 to 64 characters from the printable ASCII range 0x21-0x7E,
excluding `:`. A client secret is a non-empty string from the same range. Spaces and non-ASCII
characters are invalid in either.

Use the scrypt parameters, salt length and digest length emitted by `sg-token-broker hash-secret`.
`check-config` rejects duplicate hashes in `secret_hashes`, including two encodings of the same
hash.

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

For recovery, add `rejected_tokens_sha256`, a JSON list of at most eight full SHA-256 digests of
tokens SG rejected for this client, scope and token type. Hash the UTF-8 token string and encode
each digest as 64 lowercase hexadecimal characters. Repeat entries count toward the limit, then are
treated as one digest. Invalid input returns 400 naming the field. Omit the field for an ordinary
request. The broker evicts a matching token even if the replacement cannot be issued.

`GET /healthz` answers `{"status": "ok"}` without authentication or an SG request.

Error responses are JSON objects with `error` and `detail` fields:

| Status | `error`                | Meaning                                                                                |
| ------ | ---------------------- | -------------------------------------------------------------------------------------- |
| 400    | `bad_request`          | Malformed request or body, an unknown `token_type`, or a body sent with GET            |
| 401    | `invalid_client`       | Missing, malformed, unknown, or wrong client credentials                               |
| 403    | `forbidden`            | The client may not use the requested scope or token type                               |
| 404    | `not_found`            | Unknown path                                                                           |
| 405    | `method_not_allowed`   | Unsupported method for the path                                                        |
| 413    | `payload_too_large`    | Body larger than 8192 bytes                                                            |
| 429    | `rate_limited`         | Client's SG mint allowance is spent. `Retry-After` gives the remaining window.         |
| 500    | `internal_error`       | Unexpected error, or a script key the broker cannot read.                              |
| 502    | `sg_rejected`          | SG refused the request. Check the configured script account, key, and permissions.     |
| 502    | `sg_invalid_response`  | SG returned unusable data, including a REST lifetime of 60 seconds or less.            |
| 503    | `upstream_unavailable` | Temporary SG failure. `Retry-After` gives the wait before the broker can try SG again. |
| 503    | `server_busy`          | Broker at capacity. Retry after the indicated delay (normally 1 second).               |

The [client retry policy](#client-tuning-and-retries) applies to both the CLI and the Python
client. Check the broker audit log for the SG operation, status and any recognized code.
