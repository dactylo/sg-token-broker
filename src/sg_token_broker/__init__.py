"""sg-token-broker: temporary, scoped, audited SG credentials.

The broker services hold master SG script keys and dispense SG session or REST
tokens to authenticated callers. REST tokens have a hard SG expiry, while
session tokens follow SG's sliding inactivity lifetime. Broker cache TTLs
govern token reuse; they do not define a session token's SG lifetime. This
package provides the services and their client libraries.

Use the `sg-token-broker` CLI to serve or request tokens. Python callers use
`BrokerClient` for app tokens or `UserTokenClient` for user tokens; their
settings come from `SG_TOKEN_BROKER_*` and `SG_USER_TOKEN_*` environment
variables, respectively.
"""

from sg_token_broker._client import (
    BrokerClient,
    BrokerClientError,
    ClientOptions,
    TokenResponse,
    fetch_token,
)
from sg_token_broker._userclient import UserToken, UserTokenClient, UserTokenClientError

__all__ = [
    'BrokerClient',
    'BrokerClientError',
    'ClientOptions',
    'TokenResponse',
    'UserToken',
    'UserTokenClient',
    'UserTokenClientError',
    'fetch_token',
]
