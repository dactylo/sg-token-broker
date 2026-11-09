# Development

Use this guide to set up a development checkout, run checks, and update dependencies.

## Set up a development checkout

Install these tools before running setup:

| Tool    | Required version | Purpose                                                             |
| ------- | ---------------- | ------------------------------------------------------------------- |
| Python  | 3.11 or later    | Project interpreter, available as `python` on `PATH`                |
| uv      | 0.13.6           | Environment setup and dependency locks; other versions are rejected |
| Taplo   | 0.10.0           | TOML code blocks in Markdown                                        |
| shfmt   | 3.14.1           | Shell code blocks in Markdown                                       |
| Biome   | 2.6.6            | Repository JSON files                                               |
| Node.js | 26.12.0          | Pyright type checks                                                 |

From the repository root, run:

```sh
make setup
make check
```

To select another interpreter, use `make setup PYTHON=/path/to/python`. Setup never downloads
Python. It creates `.venv` if needed, installs the hashed pins from `requirements-ci.txt`, and
installs the project in editable mode.

Run setup again after changing `pyproject.toml` or the lock files, including when `make format`
rewrites `pyproject.toml`. Checks refuse a missing or outdated environment; they never install or
update packages.

## Run checks

| Command                 | What it does                                                             |
| ----------------------- | ------------------------------------------------------------------------ |
| `make check`            | Runs quality checks and the test suite                                   |
| `make quality`          | Checks formatting, lint, locks, types, whitespace, and workflow security |
| `make test`             | Runs the test suite                                                      |
| `make format`           | Applies formatters; inspect its changes before committing                |
| `make format-check`     | Checks formatting and lint without changing files                        |
| `make lock-check`       | Checks that dependency locks match the manifests                         |
| `make type-check`       | Checks types for Linux, macOS, and Windows                               |
| `make whitespace-check` | Checks tracked working-tree content, including committed lines           |
| `make workflow-check`   | Runs the offline zizmor audit of GitHub Actions workflows                |
| `make install`          | Installs the command with `uv tool`                                      |
| `make reinstall`        | Replaces an existing command installation                                |

`make quality` runs the same read-only checks as CI's quality job. Markdown formatting needs both
Taplo and shfmt: when either is unavailable, mdformat warns that it could not format a code block
but still succeeds. Read its warnings as well as its exit status.

## Continuous integration

The [CI workflow](../.github/workflows/ci.yml) runs `quality` first, then the `test` jobs in
parallel. `package` starts after those jobs pass; `hosted-validation` reports the overall outcome,
including failures. Pushes run every job on GitHub-hosted runners, with every test, unless the
repository variable `CI_RUN_ON_PUSH` is set to `false`.

The test matrix covers Python 3.11 to 3.15 on Linux and Python 3.13 on macOS and Windows. All test
jobs have a one-hour hang guard.

CI runs tests in parallel with pytest-xdist. Set `PYTEST_XDIST_AUTO_NUM_WORKERS` when a runner's
visible CPU count exceeds its CPU quota. For the same scheduling locally, run:

```sh
make test TEST_FLAGS='-n auto --dist worksteal --durations=15'
```

CI downloads checksum-verified Linux builds of Taplo and shfmt. The lock excludes the Python Taplo
package that `mdformat-config` would otherwise install, because it lacks some ARM wheels; CI uses
the native binary instead.

## Update dependencies

The three lock files share pins but serve different environments:

| File                     | Contents                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------ |
| `requirements-ci.txt`    | Development tools, `google`, `login`, and `oidc` extras, the `ci-build` group, and build backend |
| `requirements-test.txt`  | The smaller test-job dependency set, constrained by the CI pins                                  |
| `requirements-image.txt` | Docker dependencies, `google` and `oidc` extras, and build backend, constrained by the CI pins   |

These files do not ship with the package. Published dependency ranges stay in `pyproject.toml`. The
image installs its lock with hashes required, then builds the package without build isolation. The
`ci-build` group supplies build tools for dependencies that need source builds on supported CI
interpreters.

Use the pinned uv version to regenerate the locks:

```sh
make lock-update
make lock-check
```

For an intentional dependency upgrade, use `make lock-update LOCK_FLAGS=--upgrade`. Review all
three diffs. `make check` also includes the lock check.

The Dockerfile pins its `python:3.13-slim` base image by digest. Debian and Python patch updates
therefore require a digest change. Obtain the tag's current digest with
`docker buildx imagetools inspect python:3.13-slim`, update the Dockerfile, then rebuild and test
the image.

## Test fixtures

The `slow` pytest marker identifies long-running tests, such as the wheel-installation test. HTTP
fixtures bind ephemeral ports and write state under per-test temporary paths.
