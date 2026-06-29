# Getting started guide

This guide is the full reference for using **image-inspector**: how to install it, every command-line
option, what the interactive flow looks like, how to use it from scripts, and how the built-in
vulnerability data works.

New to the tool? The [README](../README.md) has a 60-second quick start. This page is the deep dive.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Running the tool](#running-the-tool)
- [The interactive flow](#the-interactive-flow)
- [Command-line options](#command-line-options)
- [Exit codes and environment](#exit-codes-and-environment)
- [Troubleshooting](#troubleshooting)
- [Automation and JSON output](#automation-and-json-output)
- [Vulnerability scanning](#vulnerability-scanning)
- [Running a scan yourself](#running-a-scan-yourself)
- [Supported images in detail](#supported-images-in-detail)
- [Common variants](#common-variants)
- [How it works](#how-it-works)
- [Project layout](#project-layout)

## Requirements

- To **use** the published tool: nothing but a terminal. The PyPI package bundles everything it needs,
  and it does **not** require Docker or Trivy on your machine.
- To **run from source**: Python **3.13+** and [`uv`](https://docs.astral.sh/uv/) (see the
  [Development guide](development.md)).

## Installation

### From PyPI (recommended for everyday use)

Pick whichever installer you already have:

```bash
uv tool install base-image-inspector     # via uv (recommended)
pipx install base-image-inspector        # via pipx
pip install base-image-inspector         # via pip
```

`uv tool install` and `pipx install` put the `image-inspector` command on your `PATH` in an isolated
environment, which is the cleanest option for a CLI tool.

### From source

Clone the repo and let `uv` create the environment:

```bash
git clone https://github.com/anmalkov/image-inspector.git
cd image-inspector
uv sync
uv run image-inspector
```

See the [Development guide](development.md) for the full local setup.

## Running the tool

Once installed from PyPI:

```bash
image-inspector
```

You can also run it as a Python module:

```bash
python -m image_inspector
```

From a source checkout, prefix commands with `uv run` (for example `uv run image-inspector`).

## The interactive flow

1. **Pick a language or OS.** The first menu is grouped into **Languages & runtimes** and
   **OS base images** so it is easy to scan.
2. **Pick a version.** The tool lists the latest patch of the 5 most recent minor releases (rules vary
   per image — see [Supported images in detail](#supported-images-in-detail)). LTS releases are marked.
3. **Pick a variant.** For example `slim`, `alpine`, `bookworm`, `jdk`/`jre`, or `(none)` for the plain
   tag.

The result is shown in a **sectioned panel**:

- **SELECTED** — a one-line summary of what you chose.
- **IMAGE** — the concrete image reference, creation date, compressed `linux/amd64` download size, and
  the SHA256 digest.
- **SECURITY** — vulnerability counts and scan metadata (see
  [Vulnerability scanning](#vulnerability-scanning)).
- **DOCKERFILE** — a ready-to-paste, digest-pinned `FROM` line.

After a result, an action menu lets you:

- `[f]` copy the `FROM` line to your clipboard,
- `[d]` copy the digest,
- `[n]` start a new selection,
- `[enter]` exit.

Clipboard copy uses the OSC 52 terminal escape, so it works over SSH in terminals that support it.

### Worked example: pin a Node.js image

Here is a complete interactive pass for a common Node.js base image:

```text
$ image-inspector
Select a language or OS: Node.js
Select a version: 26.3.0
Select a variant: bullseye
```

The result panel prints a full digest-pinned image reference, then a ready-to-paste Dockerfile line:

```dockerfile
FROM node:26.3.0-bullseye@sha256:5975840a23caf87319a61034f813392211a9bc41cdc0536b68e2c59da0d4f924
```

Copy the full `FROM` line from the **DOCKERFILE** section, or press `[f]` at the action menu to
copy it automatically.

## Command-line options

```bash
image-inspector --help
```

| Flag | Description |
| --- | --- |
| `--no-banner` | Skip the launch banner. |
| `--plain` | Plain, uncolored output (selection stays interactive). Also honored via the `NO_COLOR` environment variable. |
| `--json` | Non-interactive: print the resolved image as JSON. Requires `--language` and `--version`. |
| `-l`, `--language` | Image key to resolve (`python`, `dotnet`, `java`, `go`, `node`, `rust`, `cpp`, `ubuntu`, `debian`, `alpine`). |
| `--version VERSION` | Image version to resolve, e.g. `3.13.14` or `24.04`. |
| `--variant VARIANT` | Image variant, e.g. `slim` or `alpine` (`'(none)'` for the plain tag). |
| `--app-version` | Print the `image-inspector` version and exit. |

`NO_COLOR` is respected automatically (see <https://no-color.org>).

## Exit codes and environment

`image-inspector` exit codes are mode-dependent:

| Exit code | Meaning |
| --- | --- |
| `0` | Normal completion (`--json` resolution succeeds, or interactive selection flow finishes with a selected image). |
| `1` | Runtime-resolution failure: registry errors in any mode, or no matching tags for a requested `--json` version. |
| `2` | CLI usage/input issue: invalid arguments, missing `--language` / `--version` with `--json`, an unknown `--variant`, or a required `--variant` when multiple variants are available. |
| `130` | Interactive selection flow cancellation before a result is selected; also used when the interactive flow cannot continue because no selectable tags or variants are found. |

`--plain` disables Rich color output for easier scripting and log readability.
`NO_COLOR` is also honored automatically (see <https://no-color.org>).

After a result is shown, pressing `Ctrl+C`/`EOF` at the action menu exits with `0`; it does not signal failure.

## Troubleshooting

- **Clipboard copy does nothing**
  - Copy uses OSC 52 (`src/image_inspector/ui.py`).
  - Some terminals and terminal multiplexers (for example tmux without `set-clipboard on`) do not support this path, so the tool may appear to copy without visible feedback.
  - In this state, the action can still show a success message even when no text was placed on your clipboard.
  - Clipboard support is terminal-dependent, and copy failures currently do not fail the interactive flow.
  - As a workaround, copy text directly from the printed `FROM` line or switch terminals with OSC 52 support.

- **Output is still colored when I want plain text**
  - Use `--plain` for an uncolored interactive output.
  - Set `NO_COLOR` in your environment to disable color globally.

- **Network / registry errors**
  - Errors like `RegistryError` usually mean the registry could not be reached or data could not be resolved.
  - Retry after checking network access and image/tags; this is often transient.

- **Do I need Trivy or Docker locally?**
  - No. When online, the interactive panel **fetches the latest report from GitHub Pages**; when offline (or if the fetch fails) it falls back to the `report.json.gz` **bundled** with the installed release. Either way the counts come from precomputed Trivy data — fresh data no longer requires a new package release. The **SECURITY** panel's `Source` row tells you which copy you're seeing (`online (latest)` vs `offline (bundled copy)`).
  - If the published report uses a **newer schema than your installed tool understands**, the panel shows `bundled (tool outdated)` and prints a warning that you're seeing stale data — with the right upgrade command for how you installed it (`uv tool upgrade`, `pipx upgrade`, or `pip install --upgrade base-image-inspector`), or a "new version coming soon" note when the matching release isn't on PyPI yet. The tool also notifies you whenever a newer version is published on PyPI, even when the report itself is current.
  - You do **not** need Docker or Trivy installed to run image resolution locally.

## Automation and JSON output

For scripts and CI, use `--json` together with `--language` and `--version` (and optionally
`--variant`) to get machine-readable output instead of the interactive menus:

```bash
image-inspector --json -l ubuntu --version 24.04 --variant '(none)'
```

The JSON object includes the source label, language/version/variant, the resolved `image` reference,
the digest, the `pinned_reference`, the `from_line`, the compressed `size_bytes`, a `vulnerabilities`
block (critical / high / medium / low / unknown / total, plus `scanned_at`), a `scanner` block
(the Trivy version and DB date behind the counts), and a top-level `data_source`
(`"online"`, `"offline"`, or `null`) telling you whether the counts came from the live GitHub Pages
report or the bundled offline copy. When no scan data exists for the image, `vulnerabilities` is `null`.

## Vulnerability scanning

When you resolve an image, the **SECURITY** section shows how many vulnerabilities it has —
**critical**, **high** and **total** — the date the scan was taken (`Scanned`), the scanner behind
the counts (`Scanner`, the Trivy version plus the vulnerability-DB update date, e.g.
`Trivy v0.71.1 · DB Jun 14, 2026`), and where the data came from (`Source`: `online (latest)`,
`offline (bundled copy)`, or `not found`).

By default the picker is **online-first**: it fetches the latest gzipped report from **GitHub Pages**
(`https://anmalkov.github.io/image-inspector/report.json.gz`) — the live source of truth, refreshed
**nightly** by a GitHub Actions workflow that runs [Trivy](https://trivy.dev/) against every
selectable image (all versions and variants). The fetch uses a short timeout and conditional
(`ETag`) requests so it never slows the picker down, and **falls back to the `report.json.gz` bundled
with the package** whenever you're offline or the fetch fails. The bundled copy is a snapshot pinned
at release time, so it works without any network access. Nothing is pulled or scanned on your
machine, so no Docker or Trivy is required.

You can control this with environment variables:

- `IMAGE_INSPECTOR_OFFLINE=1` — skip the network fetch and always use the bundled copy.
- `IMAGE_INSPECTOR_REPORT_URL=<url>` — fetch the report from a different URL.

The report is keyed by the image's immutable **digest**, so the counts always match the exact
`name:tag@sha256:…` reference the tool pins. If an image isn't in the report yet (e.g. a brand-new
tag), the panel shows `no scan data` rather than guessing.

## Running a scan yourself

The scanner is a separate entry point. You need [Trivy](https://trivy.dev/) installed and on your
`PATH`:

```bash
image-inspector-scan                # scan every image, writes the packaged data/report.json.gz + details.json.gz
image-inspector-scan -l alpine      # only scan Alpine (repeatable: -l python -l go)
image-inspector-scan -o report.json # write somewhere else (a .gz suffix gzips, otherwise plain JSON)
```

`--language`/`-l` accepts an image key (`python`, `dotnet`, `java`, `go`, `node`, `rust`, `cpp`,
`ubuntu`, `debian`, `alpine`) and may be repeated; omit it to scan everything. Each scan also writes
a `details.json.gz` sidecar (`--details-output`) holding deduped critical/high CVE detail, loaded
lazily only for the `--dockerfile` fix-diff.

The nightly workflow uses this to **fan out one scan per language in a matrix**, then combines the
per-language reports into a single report with `image-inspector-merge`, publishing both a plain
`report.json` and a gzipped `report.json.gz` (plus the matching `details.json` sidecar) to GitHub Pages:

```bash
image-inspector-merge report-python.json report-alpine.json \
  -o pages-dir/report.json \
  --gzip-output pages-dir/report.json.gz \
  --details-inputs details-python.json details-alpine.json \
  --details-output pages-dir/details.json \
  --details-gzip-output pages-dir/details.json.gz
```

`image-inspector-merge` takes any number of partial reports and unions their tag histories, so
parallel matrix jobs still produce one combined report. In CI the combined report is **deployed to
GitHub Pages** rather than committed back to the repository.

> Running from a source checkout? Prefix these with `uv run` (e.g. `uv run image-inspector-scan`).

## Supported images in detail

- **Java** uses the Docker Official OpenJDK image (`eclipse-temurin`), which is versioned by
  *feature release* rather than `X.Y.Z`. You pick a feature version (e.g. `21`) and a variant (`jdk`,
  `jre`, `jdk-noble`, `ubi9-minimal`, …).
- **C / C++** uses the official `gcc` image — a *compiler / build* base. You'll typically multi-stage
  from it into a slim runtime (e.g. `debian:*-slim` or distroless). There is no official `clang`
  image.
- **Ubuntu** is versioned by calendar release (`YY.MM`). The picker shows the 5 newest releases
  including interim ones and tags **LTS** releases (April of an even year, e.g. `24.04`, `22.04`) so
  you can tell them apart from interim releases (e.g. `25.10`).
- **Debian** images are tagged by major release (`11`, `12`, `13`); pick `(none)` for the full image
  or `slim` for the smaller variant.

## Common variants

Variants are the suffix after a version in a registry tag. For example, `3.13.14-slim` is the
`slim` variant of Python `3.13.14`. The picker resolves variants live from the registry for the
version you choose, so the menu is always the authoritative list. Use this table as a quick
orientation guide:

| Image family | Common variants you may see |
| --- | --- |
| Python / Node.js | `(none)`, `slim`, `alpine`, `bookworm`, `bullseye`, `trixie` |
| Go / Rust / C / C++ | `(none)`, `alpine`, `bookworm`, `bullseye`, `trixie` |
| .NET SDK | `(none)`, `alpine3.23`, `noble`, `jammy`, `bookworm-slim` |
| Java (`eclipse-temurin`) | `jdk`, `jre`, `jdk-alpine`, `jre-alpine`, `jdk-noble`, `jre-noble` |
| Debian | `(none)`, `slim` |
| Ubuntu / Alpine | `(none)` |

`(none)` means the plain, suffix-less tag for that version, such as `ubuntu:24.04` or
`python:3.13.14`.

## How it works

1. Pick a language/runtime.
2. The tool queries the matching registry and lists the latest patch of the 5 newest minor versions.
3. Pick a version, then pick a variant.
4. It resolves the concrete tag to a digest, creation date and compressed size, then prints the
   pinned Dockerfile reference.

Languages and OS images come from Docker Hub; **.NET** comes from Microsoft Container Registry (MCR) —
all behind one interface.

## Project layout

```
src/image_inspector/
  cli.py        # entry point + flow orchestration
  models.py     # dataclasses + language -> registry mapping
  registry.py   # RegistryProvider protocol + Docker Hub & MCR clients
  versions.py   # tag parsing, version-scheme selection (semver/major), variants
  ui.py         # theme, banner, prompts, spinners, result panel
  report.py     # loads the Trivy vulnerability report + lazy details sidecar (online-first, bundled offline fallback)
  scanner.py    # `image-inspector-scan`: nightly Trivy scan -> report.json.gz + details.json.gz
  data/         # report.json.gz + details.json.gz fetched into the wheel at release time (git-ignored; live copy on GitHub Pages)
```

## See also

- [README](../README.md) — overview and quick start.
- [Development guide](development.md) — local setup, linting, type-checking, tests.
- [Releasing guide](releasing.md) — how releases are built and published.
