# Development guide

This guide explains how to set up a local development environment for **image-inspector**,
run the tool from source, and run the quality checks used in CI.

## Prerequisites

- **Git** – to clone the repository.
- **Python 3.13** – the project targets Python 3.13 (see `.python-version`).
- **[uv](https://docs.astral.sh/uv/)** – the package and environment manager used by this project.
  uv manages the virtual environment, dependencies, and the build/publish workflow.

Install uv (see the [official install docs](https://docs.astral.sh/uv/getting-started/installation/)
for all options):

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

uv can install the required Python version for you, so a system-wide Python 3.13 is optional.

## Clone the repository

```bash
git clone https://github.com/anmalkov/image-inspector.git
cd image-inspector
```

## Configure the development environment

Create the virtual environment and install all runtime **and** development dependencies
(`pytest`, `ruff`, `mypy`, ...):

```bash
uv sync
```

This creates a `.venv/` directory in the project root and pins the exact dependency versions from
`uv.lock`. You generally don't need to activate the environment manually — prefix commands with
`uv run` and uv uses the project environment automatically. If you prefer an activated shell:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

**Editor / type-checker setup:** point your editor's Python interpreter at `.venv` so that
auto-completion, linting, and type checking use the project's dependencies. mypy and ruff are
installed in the environment and will be picked up automatically when you run them through `uv run`.

## Run the CLI locally

The project exposes several console scripts (see `[project.scripts]` in `pyproject.toml`). Run the
main interactive command from source with:

```bash
uv run image-inspector
```

The tool is **online-first**: it fetches the gzipped vulnerability report from
[GitHub Pages](https://anmalkov.github.io/image-inspector/report.json.gz) at runtime, so a normal
online dev setup needs nothing extra. The bundled offline copy at `src/image_inspector/data/report.json.gz`
is **not committed** (it's a release-time artifact, git-ignored) — running offline from a source
checkout without it simply yields an empty report.

### Download the offline report snapshot (optional)

If you want to work offline, or run the integration tests, fetch the latest gzipped report from
GitHub Pages into the package — the same file the release workflow bundles into the wheel:

```bash
# macOS / Linux
curl --fail --location https://anmalkov.github.io/image-inspector/report.json.gz \
  -o src/image_inspector/data/report.json.gz
curl --fail --location https://anmalkov.github.io/image-inspector/details.json.gz \
  -o src/image_inspector/data/details.json.gz
```

```powershell
# Windows (PowerShell)
curl.exe --fail --location https://anmalkov.github.io/image-inspector/report.json.gz `
  -o src/image_inspector/data/report.json.gz
curl.exe --fail --location https://anmalkov.github.io/image-inspector/details.json.gz `
  -o src/image_inspector/data/details.json.gz
```

Both files are git-ignored, so they won't show up in `git status`. With them in place you can force
the offline path with `IMAGE_INSPECTOR_OFFLINE=1 uv run image-inspector`, and run the integration
tests (see below). The `details.json.gz` sidecar holds critical/high CVE detail and is loaded lazily
only for the `--dockerfile` fix-diff.

## Database stats (dev-only)

The stats view is a read-only summary of the retained scan database in `report.json` —
total digests, distinct tags, per-tag depth, active vs. retained history, the age range, how many
digests are close to aging out of the 180-day retention window, a per-image/per-version breakdown,
and the published SBOM count. It runs no scans.

It is **intentionally not a console script** (it isn't installed for end users); run it as a module:

```bash
# Live published report (default) — what's actually stored on GitHub Pages right now
uv run python -m image_inspector.stats

# The bundled snapshot (needs the offline report downloaded above)
uv run python -m image_inspector.stats --source local

# A specific report file (handy in a dev checkout) and machine-readable output
uv run python -m image_inspector.stats --report path/to/report.json --json
```

Useful flags: `--source {local,url}` (default `url`), `--report PATH` to read a file directly,
`--aging-within N` to change the near-aging-out warning window (default 14 days), `--json` for
machine-readable output, and `--plain` for uncolored text.

### Shortcut: `just stats`

Typing `uv run python -m image_inspector.stats` gets old fast. The repo ships a
[`just`](https://just.systems) task runner (`justfile`) with a `stats` recipe that wraps it and
passes flags straight through. Install `just` once (it's on PyPI, so `uv` can manage it):

```bash
uv tool install rust-just
```

Then:

```bash
just stats                                   # live report
just stats --source local                    # bundled snapshot
just stats --report path/to/report.json --json
```

Run `just --list` to see every dev task (`just check` runs the full CI gate locally).


## Quality checks

These are the same checks the CI pipeline runs on every pull request and on `main`.

### Linting

```bash
uv run ruff check .
```

### Formatting

Check formatting (CI fails if files are not formatted):

```bash
uv run ruff format --check .
```

Apply formatting locally:

```bash
uv run ruff format .
```

### Type checking

```bash
uv run mypy src
```

### Unit tests

```bash
uv run pytest
```

Run a single test file or test:

```bash
uv run pytest tests/test_cli.py
uv run pytest tests/test_cli.py::test_name
```

### Integration tests

Integration tests (under `tests/integration/`) check the real bundled `report.json.gz` and
`details.json.gz` and are **deselected from the default `uv run pytest`** because they need those
artifacts. Download the snapshots first (see [above](#download-the-offline-report-snapshot-optional)),
then run:

```bash
uv run pytest -m integration
```

This is the same check the release workflow runs after snapshotting the report from GitHub Pages.

## Before opening a pull request

Make sure all of the following pass locally:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

For how to publish a new version, see [releasing.md](./releasing.md).
