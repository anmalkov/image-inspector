# Contributing to image-inspector

Thanks for your interest in contributing! This project is early-stage, so bug reports, docs fixes,
features, and other contributions are very welcome.

## Getting set up

The full local setup (installing [uv](https://docs.astral.sh/uv/), creating the environment, and
running the tool from source) is documented in the **[Development guide](docs/development.md)**.
In short:

```bash
git clone https://github.com/anmalkov/image-inspector.git
cd image-inspector
uv sync
uv run image-inspector
```

## Branch and pull request flow

1. **Fork** the repository and create a feature branch off `main`
   (e.g. `git checkout -b fix/typo-in-readme`).
2. Make your change, keeping it focused - one logical change per pull request.
3. Run the pre-PR checks below and make sure they all pass.
4. Push your branch and open a **pull request** against `main`. Fill in the PR template.
5. A maintainer will review it. Please be patient and responsive to feedback.

## Before opening a pull request

Make sure all four checks pass locally - these are the same checks CI runs:

```bash
uv run ruff check .          # lint
uv run ruff format --check . # formatting
uv run mypy src              # type checking
uv run pytest                # tests
```

You can auto-fix formatting with `uv run ruff format .`.

## Questions

Not sure about something, or want to discuss an idea before building it? Open a thread in
**[GitHub Discussions](https://github.com/anmalkov/image-inspector/discussions)** rather than filing
an issue.

## Code of Conduct

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).
