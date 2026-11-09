import subprocess
import sys

from tests.cli_helpers import process_transcript, run_cli, run_with_closed_output


class TestImportCost:
    def test_importing_the_cli_computes_no_scrypt_hash(self) -> None:
        # A fresh interpreter, because this process has already imported the CLI.
        probe = (
            'import hashlib\n'
            'calls = []\n'
            'real = hashlib.scrypt\n'
            'hashlib.scrypt = lambda *a, **k: calls.append(1) or real(*a, **k)\n'
            'import sg_token_broker._cli\n'
            'print(len(calls))\n'
        )
        result = subprocess.run(
            [sys.executable, '-c', probe], capture_output=True, text=True, check=True
        )
        assert result.stdout.strip() == '0'


def test_closed_stdout_before_help_is_quiet() -> None:
    result = run_with_closed_output(['--help'])
    assert (result.returncode, result.stderr) == (0, b''), process_transcript(result)


def test_closed_stdout_keeps_the_hash_secret_status() -> None:
    result = run_with_closed_output(['hash-secret'])
    assert (result.returncode, result.stderr) == (0, b''), process_transcript(result)


def test_module_entry_point_runs_main() -> None:
    result = run_cli(['--help'], expect=0)
    assert result.stdout.startswith('usage: sg-token-broker '), process_transcript(result)
