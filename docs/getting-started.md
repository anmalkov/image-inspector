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
| `1` | `--json` runtime-resolution failure: registry errors, no matching tags, or variant/version mismatches. |
| `2` | `--json` input/usage issue: missing `--language` / `--version`, or invalid interactive/CLI argument combinations. |
| `130` | Interactive selection flow cancellation (menu cancel action, `Ctrl+C`, or `Ctrl+D` before a result is selected). |

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
  - No. Security counts shown in the interactive panel come from a bundled `report.json` file that is refreshed nightly in CI via Trivy runs.
  - You do **not** need Docker or Trivy installed to run image resolution locally.

## Automation and JSON output

For scripts and CI, use `--json` together with `--language` and `--version` (and optionally
`--variant`) to get machine-readable output instead of the interactive menus:

```bash
image-inspector --json -l ubuntu --version 24.04 --variant '(none)'
```

The JSON object includes the source label, language/version/variant, the resolved `image` reference,
the digest, the `pinned_reference`, the `from_line`, the compressed `size_bytes`, a `vulnerabilities`
block (critical / high / medium / low / unknown / total, plus `scanned_at`), and a `scanner` block
(the Trivy version and DB date behind the counts). When no scan data exists for the image,
`vulnerabilities` is `null`.

## Vulnerability scanning

When you resolve an image, the **SECURITY** section shows how many vulnerabilities it has —
**critical**, **high** and **total** — the date the scan was taken, and the scan source (the Trivy
version plus the vulnerability-DB update date, e.g. `Trivy v0.71.1 · DB Jun 14, 2026`).

These counts come from a JSON report (`src/image_inspector/data/report.json`) that ships with the
tool, so the interactive picker stays fast and needs no Docker or Trivy on your machine. The report is
regenerated **nightly** by a GitHub Actions workflow that runs [Trivy](https://trivy.dev/) against
every selectable image (all versions and variants) and commits the refreshed report back to the
repository.

The report is keyed by the image's immutable **digest**, so the counts always match the exact
`name:tag@sha256:…` reference the tool pins. If an image isn't in the report yet (e.g. a brand-new
tag), the panel shows `no scan data` rather than guessing.

## Running a scan yourself

The scanner is a separate entry point. You need [Trivy](https://trivy.dev/) installed and on your
`PATH`:

```bash
image-inspector-scan                # scan every image, writes the packaged data/report.json
image-inspector-scan -l alpine      # only scan Alpine (repeatable: -l python -l go)
image-inspector-scan -o report.json # write somewhere else
```

`--language`/`-l` accepts an image key (`python`, `dotnet`, `java`, `go`, `node`, `rust`, `cpp`,
`ubuntu`, `debian`, `alpine`) and may be repeated; omit it to scan everything.

The nightly workflow uses this to **fan out one scan per language in a matrix**, then combines the
per-language reports into a single `report.json` with `image-inspector-merge`:

```bash
image-inspector-merge report-python.json report-alpine.json \
  -o src/image_inspector/data/report.json
```

`image-inspector-merge` takes any number of partial reports and unions their images by digest, so
parallel matrix jobs still produce one combined report.

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
  report.py     # loads the bundled Trivy vulnerability report
  scanner.py    # `image-inspector-scan`: nightly Trivy scan -> report.json
  data/         # bundled report.json (refreshed nightly in CI)
```

## See also

- [README](../README.md) — overview and quick start.
- [Development guide](development.md) — local setup, linting, type-checking, tests.
- [Releasing guide](releasing.md) — how releases are built and published.
