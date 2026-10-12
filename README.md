# sg-token-broker

sg-token-broker lets pipeline tools call Autodesk Flow Production Tracking without receiving
long-lived API script keys. A service you run keeps the keys, checks each caller, and issues an SG
token with the permissions of a configured script account or of the signed-in person.

Use it when farm jobs, pipeline services, desktop tools, or Google Sheets need SG access and you
want to keep script keys on one host, limit which SG identities each caller can use, and record
every issuance in an audit log.

This documentation uses SG for Flow Production Tracking, formerly named Shotgun and ShotGrid.

## Choose a service

Choose by whose permissions SG should enforce:

- **App-token broker:** for farm jobs, pipeline services, and shared tools. Each named *scope* maps
  to an SG script account with a limited permission role, and each consuming system gets its own
  broker credential.
- **User-token service:** for tools that act as the signed-in person. The service verifies the
  person's studio sign-in and issues a token bound to their own SG account.

Both services issue REST tokens and session tokens. Existing `shotgun_api3` integrations need
session tokens, and user session tokens require a private deployment on a restricted network. See
[Choosing a credential](docs/modes.md) for the tradeoffs.

## Installation

You need Python 3.11 or later and [uv](https://docs.astral.sh/uv/). Running either service also
requires an SG site and an SG administrator who can create script accounts.

From a checkout of this repository, install the `sg-token-broker` command:

```sh
uv tool install .
sg-token-broker --help
```

After pulling changes, update it with `uv tool install --reinstall .`. The app-token broker and its
clients need no extras. Add an extra, as in `uv tool install '.[login]'`, for these features:

- `login`: stores a desktop sign-in in the operating system's keyring, so later commands do not
  open a browser.
- `google`: lets the user-token service verify Google Workspace ID tokens.
- `oidc`: lets the user-token service verify ID tokens from another OIDC provider.

For Python integrations, install the package into the environment that runs your application, for
example with that environment's `python -m pip install /path/to/sg-token-broker`. The
`shotgun_api3` examples also need the SG Python API in that environment. A `uv tool` installation
does not make the library importable from other environments.

## Quick start

This walkthrough runs the app-token broker on your machine and fetches a token for one scope. First
ask an SG administrator to create a script account, such as `broker_read_all`, whose permission
role grants only what your tool needs. Only the broker uses that account's application key.

### Create a client credential

```sh
sg-token-broker hash-secret
```

The command prints a `secret:` line for the consuming tool and a `hash:` line for the broker
configuration. The broker stores only the hash.

### Configure the broker

Save this as `broker.yml`, replacing the site URL and `secret_hash` with your values:

```yaml
site_url: https://your-site.shotgrid.autodesk.com
server:
  bind: 127.0.0.1
  port: 8743
scopes:
  read_all:
    script_name: broker_read_all
    script_key_env: SGTB_KEY_READ_ALL
clients:
  farm_render:
    secret_hash: paste-the-generated-hash-here
    scopes: [read_all]
```

The `read_all` scope maps to the `broker_read_all` script account, whose key the broker reads from
the `SGTB_KEY_READ_ALL` environment variable. The `farm_render` client may request only that scope.

### Start the broker

Supply the script account's key, validate the configuration, and start the broker:

```sh
export SGTB_KEY_READ_ALL='your-script-application-key'
sg-token-broker check-config --config broker.yml
sg-token-broker serve-app-tokens --config broker.yml
```

`check-config` prints `ok: 1 scope(s), 1 client(s)`. The broker then reports
`serving on http://127.0.0.1:8743` and keeps running. It accepts plain HTTP here only because it
listens on loopback; any other address requires TLS.

### Request a token

In another terminal, configure the client and request a token:

```sh
export SG_TOKEN_BROKER_URL='http://127.0.0.1:8743'
export SG_TOKEN_BROKER_CLIENT_ID='farm_render'
export SG_TOKEN_BROKER_CLIENT_SECRET='the-generated-client-secret'
sg-token-broker get-token --scope read_all
```

The command prints JSON with the SG session token in `token`, along with `token_type`, `scope`,
`site_url`, and `expires_at`. Add `--token-type rest` for a REST bearer token. Treat either token
as a credential. The broker's terminal shows one JSON `issue` record for the request, which
identifies the token without including it.

In Python, with this package and `shotgun_api3` installed in your application's environment:

```python
import shotgun_api3

from sg_token_broker import BrokerClient

token = BrokerClient().fetch_token('read_all')
sg = shotgun_api3.Shotgun(token.site_url, session_token=token.token)
```

`BrokerClient` reads the same three environment variables and reuses its token until shortly before
`expires_at`.

This setup listens only on your machine. Before shared use, follow the
[app-token broker deployment](docs/deployment.md) guide for TLS, secret storage, and operations.
Session tokens stay valid while in use, and rotating a script key does not revoke them; read
[token lifetime and revocation](docs/sg-token-behavior.md) before deploying.

## Use the signed-in person's permissions

Deploy the [user-token service](docs/user-token-service.md) for tools that need the caller's own SG
permissions. Choose the Cloud Run deployment for Google Workspace callers that use REST, or a
private deployment for session tokens used by `shotgun_api3`.

If your administrator already runs the service, start with
[desktop client setup](docs/user-token-service.md#desktop-client-setup) or the
[Apps Script caller](docs/user-token-service.md#apps-script-caller).

## Documentation

| If you want to...                                                | Read                                                            |
| ---------------------------------------------------------------- | --------------------------------------------------------------- |
| Choose between app and user tokens, or session and REST tokens   | [Choosing a credential](docs/modes.md)                          |
| Deploy, operate, or troubleshoot the app-token broker            | [App-token broker deployment](docs/deployment.md)               |
| Deploy the user-token service                                    | [User-token service](docs/user-token-service.md)                |
| Connect a desktop tool or Google Sheet to the user-token service | [Client setup](docs/user-token-service.md#desktop-client-setup) |
| Handle token expiry or respond to a leaked credential            | [Token lifetime and revocation](docs/sg-token-behavior.md)      |
| Understand the security boundaries and their limits              | [Design and security](docs/design.md)                           |
| See changes by version                                           | [Changelog](CHANGELOG.md)                                       |

## Development

See the [development guide](docs/development.md) for the required tools, CI, and dependency locks.
With those tools installed, run:

```sh
make setup
make check
```

The checks use a local fake SG server and never contact a live site.

## License

sg-token-broker is available under the [MIT License](LICENSE). It is an independent project and is
not affiliated with or endorsed by Autodesk. Flow Production Tracking is a product of Autodesk,
Inc.
