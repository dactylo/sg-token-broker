import importlib.util
from pathlib import Path
from types import ModuleType

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


def load_script(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
