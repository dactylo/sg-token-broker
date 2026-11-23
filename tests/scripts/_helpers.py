import importlib.util
from functools import cache
from pathlib import Path
from types import ModuleType

from tests._timeouts import STALL_TIMEOUT_SECONDS

# Each verification script accepts HTTPS site URLs and plain HTTP only on loopback.
ACCEPTED_SITE_URLS = (
    'https://studio.example',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://[::1]:8080',
)
REJECTED_SITE_URLS = (
    'http://sg.studio.internal',
    'http://evil.example\\@localhost',
    '\x00https://studio.example',
    ' https://studio.example',
    'https://studio.example/path with space',
    'https://studio.example:notaport',
    'https://studio.example:65536',
    'http://10.1.2.3',
    'ftp://studio.example',
    'https://',
    'not-a-url',
)


def load_script(path: Path, *, lift_stall_detectors: bool = True) -> ModuleType:
    return _load_script(path, lift_stall_detectors=lift_stall_detectors)


@cache
def _load_script(path: Path, *, lift_stall_detectors: bool) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if lift_stall_detectors:
        if path.stem in {'verify_sg_revocation', 'verify_sg_sudo'}:
            assert '_TIMEOUT_SECONDS' in vars(module), 'script request deadline setting is missing'
            vars(module)['_TIMEOUT_SECONDS'] = STALL_TIMEOUT_SECONDS
        elif path.stem == 'verify_sg_human_session':
            assert '_REQUEST_TIMEOUT' in vars(module), 'script request deadline setting is missing'
            vars(module)['_REQUEST_TIMEOUT'] = (STALL_TIMEOUT_SECONDS, STALL_TIMEOUT_SECONDS)
    return module
