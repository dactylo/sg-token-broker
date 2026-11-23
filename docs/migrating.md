# Replacing script keys in existing code

Choose the identity your existing `shotgun_api3` tool needs. A farm job or background service can
use a broker scope tied to a script account. A tool that acts for the person running it can use
their own SG session. In both cases the script key stays on the service.

Install the package from a checkout into the Python environment that already runs your tool and
imports `shotgun_api3`. Use that application's Python 3.11 or later, for example:

```sh
/path/to/app/bin/python -m pip install /path/to/sg-token-broker
```

On Windows, the equivalent in PowerShell is:

```powershell
& 'C:\path\to\app\Scripts\python.exe' -m pip install 'C:\path\to\sg-token-broker'
```

## Move an unattended job to a broker scope

Ask the operator for the broker URL, a client credential, and a scope that grants the SG actions
your job needs. Supply the secret through the job account's environment or load it from a file
readable only by that account. Keep it out of source control and visible job settings. See
[Configure client environments](deployment.md#configure-client-environments).

Replace `Shotgun(site, script_name=script_name, api_key=script_key)` with:

```python
from shotgun_api3 import Shotgun
from sg_token_broker import BrokerClient

broker = BrokerClient()
token = broker.fetch_token('read_all')
sg = Shotgun(token.site_url, session_token=token.token)
```

Keep the broker client for the life of the process so it can reuse tokens and remember rejections.
Existing reads and writes through `sg` use the scope's script-account permissions.

A machine people also use can run unattended jobs with a broker credential when those jobs run
under their own account and only that account can read the credential. If jobs run as the logged-in
person, that person can read the credential and act as the script account.

## Move a tool that acts as the signed-in person

Replace the admin script key and `sudo_as_login` with a session from a private user-token service.
Complete [desktop client setup](user-token-service.md#desktop-client-setup) first. To reuse the
sign-in across runs, install the checkout with its `login` extra in the application's environment.

```python
from shotgun_api3 import Shotgun
from sg_token_broker import UserTokenClient

client = UserTokenClient()
token = client.fetch_token('session')
sg = Shotgun(token.site_url, session_token=token.token)
```

The service maps the verified sign-in to an SG account. Remove any option that let the tool choose
a target login. Operations that must act for someone else need a separately authorized service.

## Recover a read when SG rejects the session

When SG rejects an app token, pass it to `broker.fetch_token` as `rejected_token` to get a
replacement. Use the token from the connection that failed, even if your broker client has since
fetched another one. Set `serving_processes` to the number of brokers behind your endpoint. The
four-peer reference allows six SG reads and requests a replacement only when another read is
available.

```python
from shotgun_api3 import AuthenticationFault, Shotgun


def find_project(broker, token, project_id, serving_processes=4):
    read_limit = serving_processes + 2
    for read_number in range(1, read_limit + 1):
        try:
            sg = Shotgun(token.site_url, session_token=token.token)
            return sg.find_one('Project', [['id', 'is', project_id]], ['name'])
        except AuthenticationFault:
            if read_number == read_limit:
                raise RuntimeError(
                    'SG rejected every token tried; check the script account'
                ) from None
        token = broker.fetch_token('read_all', rejected_token=token.token)
```

Pass the same `broker` and the `read_all` token from the job example. A `BrokerClientError` from
`fetch_token` propagates with the broker diagnosis. The script-account error means that SG rejected
every token tried. A starting token older than every process's cache can require a rejection report
for that token and another for each process's stale token. Four reads cover two processes. See
[Replacing a rejected app token](sg-token-behavior.md#replacing-a-rejected-app-token) for shell
callers and the supported process count.

For a user session, call `client.fetch_token('session', force_refresh=True)` after an
`AuthenticationFault` and rebuild the SG connection with the result. The service checks a cached
session with SG before replacing it. Keep automatic replay limited to reads. After a write times
out or loses its connection, check whether SG applied it before deciding whether to send it again.

## Cut over and retire the old keys

1. Inventory embedded keys and all their callers, including deployed copies and long-running jobs.
2. Create script accounts with the permissions each job needs, and map broker scopes to them.
   Configure the private user-token service for callers that act as people.
3. Migrate one caller. Verify an intended SG action succeeds and an action outside the intended
   permissions is denied. Use test data for this check.
4. Distribute client credentials outside source control, roll out the remaining callers, and
   restart processes still using embedded keys.
5. Regenerate every script key that was ever committed. Removing it from today's source leaves it
   in history. Regeneration stops new use of the key, but sessions already issued can remain
   active. To retire them, follow
   [Retire a compromised script account](deployment.md#retire-a-compromised-script-account).
