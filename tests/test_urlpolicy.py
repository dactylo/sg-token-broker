import pytest

from sg_token_broker._urlpolicy import is_loopback_host, require_https_or_loopback


class TestRequireHttpsOrLoopback:
    @pytest.mark.parametrize(
        'url',
        [
            'https://studio.shotgunstudio.com',
            'https://broker.studio.internal:8743',
            'http://localhost:8743',
            'http://127.0.0.1:8743',
            'http://[::1]:8743',
        ],
    )
    def test_accepts_https_and_loopback_http(self, url: str) -> None:
        assert require_https_or_loopback(url, 'site_url') == url

    def test_rejects_backslash_authority(self) -> None:
        with pytest.raises(ValueError, match='site_url'):
            require_https_or_loopback('http://evil.example\\@localhost', 'site_url')

    @pytest.mark.parametrize(
        'url',
        [
            'https://studio.example:notaport',
            'https://studio.example:65536',
            'http://localhost:notaport',
            'http://127.0.0.1:65536',
        ],
    )
    def test_rejects_invalid_ports(self, url: str) -> None:
        with pytest.raises(ValueError, match='site_url'):
            require_https_or_loopback(url, 'site_url')

    @pytest.mark.parametrize(
        'url',
        [
            'http://broker.studio.internal:8743',
            'http://10.1.2.3',
            'http://localhost.evil.example',
            'ftp://studio.example',
            'https://',
            'not-a-url',
            'http://[::1',
        ],
    )
    def test_rejects_plaintext_and_malformed(self, url: str) -> None:
        with pytest.raises(ValueError, match='site_url'):
            require_https_or_loopback(url, 'site_url')

    @pytest.mark.parametrize(
        'url',
        [
            '\x00https://studio.example',
            '\thttps://studio.example',
            ' https://studio.example',
            'https://studio .example',
            'https://studio.example/path with space',
            'https://studio.example/path\tsegment',
            'https://studio.example/?q=a\nb',
            'http://localhost/#a\rb',
            'http://localhost/\x7f',
            'https://studio.example/\N{NO-BREAK SPACE}',
        ],
    )
    def test_rejects_raw_control_or_whitespace(self, url: str) -> None:
        with pytest.raises(ValueError, match='site_url'):
            require_https_or_loopback(url, 'site_url')


@pytest.mark.parametrize('host', ['localhost', 'LOCALHOST', '127.0.0.1', '::1'])
def test_is_loopback_host_accepts_names_and_addresses(host: str) -> None:
    assert is_loopback_host(host)
