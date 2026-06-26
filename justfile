# Dev task runner for image-inspector (https://just.systems).
#
# Install `just` once (it is published on PyPI, so uv can install it):
#     uv tool install rust-just
# Then run any task below, e.g. `just stats` or `just check`.
#
# These tasks are dev-only conveniences; they are not part of the published package.

# Use PowerShell on Windows; other platforms use the default `sh`.
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Show the list of available tasks.
default:
    @just --list

# Database stats over the retained report.json (dev-only). Pass flags through, e.g.
# `just stats --source local`, `just stats --json`, `just stats --report path/to/report.json`.
stats *args:
    @uv run python -m image_inspector.stats {{args}}

# Run the interactive picker from source.
run *args:
    uv run image-inspector {{args}}

# Lint with ruff.
lint:
    uv run ruff check .

# Check formatting (does not modify files).
fmt-check:
    uv run ruff format --check .

# Apply formatting.
fmt:
    uv run ruff format .

# Type-check the package.
typecheck:
    uv run mypy src

# Run the unit tests.
test *args:
    uv run pytest {{args}}

# Run every check CI runs (lint, formatting, types, tests).
check: lint fmt-check typecheck test
