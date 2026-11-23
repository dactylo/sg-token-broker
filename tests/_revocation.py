import re

ISSUED_SESSION = 'live-session'
REPLACEMENT_KEY = 'replacement-key'


def assert_operator_steps(
    prompts: list[str], count: int, *, replacement_key: bool = False
) -> None:
    actions = [
        ('regenerate', 'key'),
        ('disable', 'apiuser'),
        ('restore', 'apiuser'),
        ('optional', 'rotate', 'rename', 'trash', 'new script', 'original name', 'fresh key'),
    ]
    if replacement_key:
        *prompts, secret_prompt = prompts
        assert all(word in secret_prompt.lower() for word in ('replacement', 'key', 'skip'))
    assert len(prompts) == count
    for prompt, fragments in zip(prompts, actions[:count], strict=True):
        assert re.search(r'\bs\b', prompt)
        remaining = prompt.lower()
        for fragment in fragments:
            assert fragment in remaining, prompt
            remaining = remaining.split(fragment, 1)[1]


def assert_replacement_procedure(output: str, verdict: str) -> None:
    procedures = [line for line in output.splitlines() if verdict in line]
    assert len(procedures) == 1
    assert re.search(
        r'\brotate\b.*\brename\b.*(?:permanently trash|trash\b.*?\bpermanently)\b'
        r'.*\breplace(?:ment)?\b.*\bscript (?:reusing|with) the original name\b',
        procedures[0],
    ), procedures[0]


def assert_restore_reminder(output: str, *, after: str) -> None:
    _, marker, following = output.partition(after)
    assert marker, f'missing branch result: {after}'
    assert any(
        re.search(r'\bs\b', line)
        and all(
            word in line.lower()
            for word in ('restore', 'trashed', 'sg admin', 'unless', 'retired')
        )
        for line in following.splitlines()[1:]
    )
