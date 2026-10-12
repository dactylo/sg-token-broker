import importlib.machinery
import importlib.metadata
import os
import shutil
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

from tests.cli_helpers import process_transcript, run_cli, run_setup

ROOT = Path(__file__).resolve().parents[1]


def _assert_extracted_wheel(installed: Path, expected_version: str) -> None:
    package = importlib.machinery.PathFinder.find_spec('sg_token_broker', [str(installed)])
    assert package is not None
    assert package.origin == str(installed / 'sg_token_broker' / '__init__.py')
    distributions = [
        item
        for item in importlib.metadata.distributions(path=[str(installed)])
        if item.metadata['Name'] == 'sg-token-broker'
    ]
    assert len(distributions) == 1
    assert distributions[0].version == expected_version


def _build(project: Path, target: str) -> Path:
    result = run_setup(
        [sys.executable, '-m', 'hatchling', 'build', '-t', target], cwd=project, check=False
    )
    assert result.returncode == 0, process_transcript(result)
    suffix = '*.whl' if target == 'wheel' else '*.tar.gz'
    return next((project / 'dist').glob(suffix))


def _copy_project(destination: Path) -> None:
    destination.mkdir()
    for name in ('pyproject.toml', 'README.md', 'LICENSE'):
        shutil.copy2(ROOT / name, destination / name)
    shutil.copytree(
        ROOT / 'src',
        destination / 'src',
        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'),
    )


@pytest.mark.slow
def test_installed_wheel_reports_its_version(tmp_path: Path) -> None:
    project = tmp_path / 'project'
    _copy_project(project)
    expected = tomllib.loads((project / 'pyproject.toml').read_text(encoding='utf-8'))['project'][
        'version'
    ]
    wheel = _build(project, 'wheel')
    installed = tmp_path / 'installed'
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.namelist():
            archive.extract(member, installed)
    _assert_extracted_wheel(installed, expected)

    result = run_cli(
        ['--version'],
        expect=0,
        cwd=tmp_path,
        env={**os.environ, 'PYTHONPATH': str(installed)},
    )
    assert result.stdout == f'sg-token-broker {expected}\n', process_transcript(result)
