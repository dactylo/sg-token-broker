from tests.cli_helpers import process_transcript, run_cli, run_with_closed_output
from tests.conftest import BROKER_CREDENTIAL


def test_closed_stdout_before_help_is_quiet() -> None:
    result = run_with_closed_output(['--help'])
    assert (result.returncode, result.stderr) == (0, b''), process_transcript(result)


def test_closed_stdout_keeps_the_hash_secret_status() -> None:
    result = run_with_closed_output(['hash-secret', '--secret', BROKER_CREDENTIAL])
    assert (result.returncode, result.stderr) == (0, b''), process_transcript(result)


def test_module_entry_point_runs_main() -> None:
    result = run_cli(['--help'], expect=0)
    assert result.stdout.startswith('usage: sg-token-broker '), process_transcript(result)
