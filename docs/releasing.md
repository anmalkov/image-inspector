# Releasing guide

Releases are fully automated by the **Release** workflow
([`.github/workflows/release.yml`](../.github/workflows/release.yml)). Pushing a version tag builds
the package, publishes it to [PyPI](https://pypi.org/project/base-image-inspector/), and creates a GitHub
Release.

## One-time setup: PyPI Trusted Publishing

The release workflow publishes to PyPI using **Trusted Publishing (OIDC)** — no API tokens or secrets
are stored in the repository. This must be configured **once** before the first release:

1. Sign in to [PyPI](https://pypi.org/) as a maintainer of the `base-image-inspector` project.
2. Go to the project's **Settings → Publishing** (or, for the very first release, add a
   *pending* publisher under your account's **Publishing** settings).
3. Add a new **GitHub Actions** trusted publisher with:
   - **Owner:** `anmalkov`
   - **Repository:** `image-inspector`
   - **Workflow name:** `release.yml`
   - **Environment:** `pypi`
4. Save. The workflow's `pypi` environment and `id-token: write` permission match this configuration.

Until this is configured, the publish step will fail.

## Versioning

The version is derived **from the git tag** at release time:

- Tags must follow `vX.Y.Z` (for example `v0.1.0`, `v1.2.3`).
- The workflow strips the leading `v` and runs `uv version <X.Y.Z>`, which updates the version in
  `pyproject.toml`. `uv build` then bakes that version into the published package metadata.
- At runtime the package reports its version via `importlib.metadata` (see
  `src/image_inspector/__init__.py`), so there is **no** version file to edit by hand.

> **Important:** PyPI versions are immutable — a version can only be published once. Never reuse or
> re-push a tag/version. Always bump to a new, unique version for each release.

## Cutting a release

1. Make sure `main` is green (CI passing) and contains everything you want to ship.
2. Decide the new version number, e.g. `0.1.0`.
3. Create and push the tag from `main`:

   ```bash
   git checkout main
   git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. The **Release** workflow triggers automatically and will:
   - verify the tagged commit is on `main` (the release fails fast otherwise),
   - set the project version from the tag (`uv version`),
   - **snapshot the latest report from GitHub Pages** into `src/image_inspector/data/report.json`
     so the wheel ships a release-pinned offline fallback (see below),
   - **verify the tool can read its own bundled report** and fail the release otherwise,
   - build the source distribution and wheel (`uv build`),
   - publish them to PyPI via Trusted Publishing (`uv publish`),
   - create a GitHub Release for the tag with auto-generated notes and the built
     artifacts attached.

   > Tags are not tied to a branch in Git, so the workflow guards against accidental releases by
   > checking that the tagged commit is reachable from `main`. Always tag a commit that is already on
   > `main`.

5. Verify the result:
   - the [GitHub Releases page](https://github.com/anmalkov/image-inspector/releases) shows the new release,
   - the new version appears on [PyPI](https://pypi.org/project/base-image-inspector/),
   - `uv tool install base-image-inspector` (or `pip install base-image-inspector`) installs the new version.

## Offline report snapshot

At runtime the tool is **online-first**: it fetches the latest vulnerability report from
[GitHub Pages](https://anmalkov.github.io/image-inspector/report.json) and only falls back to the
copy bundled in the wheel when offline. To keep that bundled fallback fresh, the release workflow
has a **"Snapshot the latest Pages report into the package"** step that runs *before* `uv build`:
it downloads the current Pages `report.json` into `src/image_inspector/data/report.json` so each
release ships a release-pinned offline snapshot.

This is why the nightly scan job publishes the report to Pages rather than committing it back to the
repo — the bundled copy is refreshed here, at release time, instead.

The snapshot step **fails soft**: if the download fails, times out, or doesn't return parseable
JSON, it logs a warning and keeps whatever `report.json` is already committed, so a transient Pages
hiccup never blocks a release. The snapshot deliberately does **not** re-validate the report's
schema — deciding whether a report is usable is the tool's job, not the workflow's.

That check is instead enforced as a hard **release gate** by the next step, *"Verify the tool
accepts the bundled report"*. It loads the bundled copy through `image_inspector` itself
(`IMAGE_INSPECTOR_OFFLINE=1`) and **fails the release** if the tool rejects it or it loads empty.
Because the gate runs the real loader, the definition of "valid" lives entirely in the package and
the workflow never needs updating when the report format or schema version changes.

## Package metadata

The published package's **name**, **description**, and other metadata come from the `[project]`
section of `pyproject.toml`. Update that section (and the `README.md`, which is used as the long
description) before tagging if any of it needs to change.
