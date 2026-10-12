import sg_token_broker


class TestPublicAPI:
    def test_exports(self) -> None:
        assert set(sg_token_broker.__all__) == {
            'BrokerClient',
            'BrokerClientError',
            'ClientOptions',
            'TokenResponse',
            'UserToken',
            'UserTokenClient',
            'UserTokenClientError',
            'fetch_token',
        }

    def test_symbols_resolve(self) -> None:
        for name in sg_token_broker.__all__:
            assert getattr(sg_token_broker, name) is not None
