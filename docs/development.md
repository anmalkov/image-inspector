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

## Before opening a pull request

Make sure all of the following pass locally:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

For how to publish a new version, see [releasing.md](./releasing.md).
