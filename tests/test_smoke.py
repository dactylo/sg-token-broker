from sg_token_broker import BrokerClient
from tests._timeouts import STALL_TIMEOUT_SECONDS
from tests.conftest import BROKER_CREDENTIAL, FakeSG

_SESSION_TYPE = 'session'


class TestSmoke:
    def test_full_token_flow(self, fake_sg: FakeSG, broker_url: str) -> None:
        client = BrokerClient(
            broker_url,
            'farm',
            BROKER_CREDENTIAL,
            timeout=STALL_TIMEOUT_SECONDS,
            retries=0,
            max_wait=STALL_TIMEOUT_SECONDS,
        )

        session = client.fetch_token('read_all')
        assert session.token == fake_sg.canned_session
        assert session.token_type == _SESSION_TYPE
        assert session.site_url == fake_sg.url

        rest = client.fetch_token('read_all', 'rest')
        assert rest.token == fake_sg.canned_rest

        again = client.fetch_token('read_all')
        assert again.token == session.token

        rpc_bodies = [r for r in fake_sg.requests if r['path'] == '/api3/json']
        assert len(rpc_bodies) == 1  # second session fetch was served from cache
