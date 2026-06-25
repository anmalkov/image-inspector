# Copilot instructions for image-inspector

Interactive CLI to pick and digest-pin official container base images and show precomputed
Trivy vulnerability counts. Python 3.13+, packaged with `uv`. Source lives in
`src/image_inspector/`, tests in `tests/`.

## Always validate before committing

CI (`.github/workflows/ci.yml`) runs **four** checks and fails the PR if any fail. Run the
**exact same commands locally and make them all pass before you commit** — do not rely on
`ruff check` alone, since formatting (`ruff format --check`) is a separate check that lint
does not cover:

```bash
uv run ruff check .          # lint
uv run ruff format --check . # formatting (CI fails if files would be reformatted)
uv run mypy src              # type-check
uv run pytest                # tests
```

If `ruff format --check .` reports files that "would be reformatted", run `uv run ruff format .`
to fix them, then re-run the checks and commit the result.

## Conventions

- Keep line length ≤ 100 (`ruff` is configured for this).
- Tests must not make real network calls — mock HTTP with `respx` (a dev dependency). The
  `tests/conftest.py` autouse fixture forces the report loader offline by default.
- `uv run pytest` runs unit tests only; integration tests (marked `integration`, under
  `tests/integration/`) are deselected by default because they depend on the bundled
  `report.json`, which is **not committed** — it is fetched from GitHub Pages into the wheel
  at release time. The release workflow runs them with `uv run pytest -m integration`.
- Prefer small, surgical changes; only comment code that genuinely needs clarification.
