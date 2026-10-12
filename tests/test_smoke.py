from sg_token_broker import BrokerClient
from tests.conftest import BROKER_CREDENTIAL, _FakeSG


class TestSmoke:
    def test_full_token_flow(self, fake_sg: _FakeSG, broker_url: str) -> None:
        client = BrokerClient(broker_url, 'farm', BROKER_CREDENTIAL)

        session = client.fetch_token('read_all')
        assert session.token == fake_sg._canned_session
        assert session.site_url == fake_sg._url

        rest = client.fetch_token('read_all', 'rest')
        assert rest.token == fake_sg._canned_rest
        assert 'refresh' not in rest.token

        again = client.fetch_token('read_all')
        assert again.token == session.token

        rpc_bodies = [r for r in fake_sg._requests if r['path'] == '/api3/json']
        assert len(rpc_bodies) == 1  # second session fetch was served from cache
