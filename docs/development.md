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

The tool is **online-first**: it fetches the vulnerability report from
[GitHub Pages](https://anmalkov.github.io/image-inspector/report.json) at runtime, so a normal
online dev setup needs nothing extra. The bundled offline copy at `src/image_inspector/data/report.json`
is **not committed** (it's a release-time artifact, git-ignored) — running offline from a source
checkout without it simply yields an empty report.

### Download the offline report snapshot (optional)

If you want to work offline, or run the integration tests, fetch the latest report from GitHub Pages
into the package — the same file the release workflow bundles into the wheel:

```bash
# macOS / Linux
curl --fail --location https://anmalkov.github.io/image-inspector/report.json \
  -o src/image_inspector/data/report.json
```

```powershell
# Windows (PowerShell)
curl.exe --fail --location https://anmalkov.github.io/image-inspector/report.json `
  -o src/image_inspector/data/report.json
```

The file is git-ignored, so it won't show up in `git status`. With it in place you can force the
offline path with `IMAGE_INSPECTOR_OFFLINE=1 uv run image-inspector`, and run the integration tests
(see below).

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

Integration tests (under `tests/integration/`) check the real bundled `report.json` and are
**deselected from the default `uv run pytest`** because they need that artifact. Download the
snapshot first (see [above](#download-the-offline-report-snapshot-optional)), then run:

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
