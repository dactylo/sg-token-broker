from pathlib import Path

import pytest

from tests.scripts._helpers import ACCEPTED_SITE_URLS, REJECTED_SITE_URLS, load_script

_SCRIPTS = Path(__file__).parents[2] / 'scripts'


@pytest.mark.parametrize('script_name', ['revocation', 'sudo'])
@pytest.mark.parametrize('url', ACCEPTED_SITE_URLS)
def test_accepts_https_and_loopback_http(script_name: str, url: str) -> None:
    validator = load_script(_SCRIPTS / f'verify_sg_{script_name}.py')._require_https_or_loopback
    assert validator(url) == url


@pytest.mark.parametrize('script_name', ['revocation', 'sudo'])
@pytest.mark.parametrize('url', REJECTED_SITE_URLS)
def test_rejects_unsafe_or_malformed_urls(script_name: str, url: str) -> None:
    validator = load_script(_SCRIPTS / f'verify_sg_{script_name}.py')._require_https_or_loopback
    with pytest.raises(ValueError, match='site URL'):
        validator(url)
