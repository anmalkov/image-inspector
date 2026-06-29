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
- [Inspecting a Dockerfile](#inspecting-a-dockerfile)
- [Vulnerability scanning](#vulnerability-scanning)
- [History, retention and "latest tracked digest"](#history-retention-and-latest-tracked-digest)
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
| `--json` | Non-interactive: print the resolved image as JSON. Requires `--language` and `--version` — or use it with `--dockerfile` to print the per-stage comparison as JSON. |
| `-l`, `--language` | Image key to resolve (`python`, `dotnet`, `java`, `go`, `node`, `rust`, `cpp`, `ubuntu`, `debian`, `alpine`). |
| `--version VERSION` | Image version to resolve, e.g. `3.13.14` or `24.04`. |
| `--variant VARIANT` | Image variant, e.g. `slim` or `alpine` (`'(none)'` for the plain tag). |
| `--dockerfile PATH` | Inspect an existing Dockerfile: compare each `FROM` image's pinned digest against the latest tracked digest (see [Inspecting a Dockerfile](#inspecting-a-dockerfile)). Combine with `--json` for machine-readable output. |
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

## Inspecting a Dockerfile

If you already have a `Dockerfile`, `--dockerfile <path>` inspects every `FROM` instruction and
compares the **digest you pinned** against the **latest tracked digest** for that tag, so you can see
at a glance whether moving to the newest image would reduce your vulnerability exposure:

```bash
image-inspector --dockerfile ./Dockerfile
```

This reads the file, parses each `FROM` (resolving global `ARG` defaults and recognising
multi-stage builds), and prints one block per stage. No images are pulled and nothing is scanned
locally — the comparison is purely against the precomputed nightly data.

### Per-stage status

Each `FROM` stage is classified into one of these statuses:

| Status | Meaning |
| --- | --- |
| `pinned_known` | A digest is pinned **and** the report has scan data for it. The full pinned-vs-latest diff (including the critical/high fix-diff) is shown. |
| `pinned_unknown` | A digest is pinned but it is no longer tracked (it aged out, or is too new). The tag's latest tracked digest is shown instead, so you still get a comparison target. |
| `tag_known` | No digest is pinned, but the tag's latest digest is tracked. The latest counts are shown. |
| `untracked` | Neither the pinned digest nor the tag is in the report (e.g. an unsupported image, or a brand-new tag). Reported plainly, without guessing. |
| `skipped` | The `FROM` references an earlier build stage (e.g. `FROM build`) or depends on an unresolved `ARG`, so there is nothing to look up. The reason is noted. |

Docker Hub references are normalised, so `python`, `library/python` and `docker.io/library/python`
all resolve to the same tracked image. Images on other registries (for example
`mcr.microsoft.com/...`) are matched as-is.

### Reading the output

For a pinned image with scan data, a stage block shows the pinned digest's counts, a
**LATEST DIGEST** section (the latest digest's counts, when it was built, and a ready-to-paste
`FROM` line), and a **DIFFERENCES** section:

```text
✓ dockerfile
  DOCKERFILE
    Path     ./Dockerfile
    Stages   2 FROM instruction(s)

  [1] FROM python:3.13-slim@sha256:abc...
    Status           pinned digest tracked
    Vulnerabilities  Critical: 1  ·  High: 3  ·  Total: 27
    LATEST DIGEST
    FROM             python:3.13-slim@sha256:205e60d0b78f024817...
    Created          Jun 22, 2026 · 00:00 UTC
    Vulnerabilities  Critical: 0  ·  High: 1  ·  Total: 23  ✓ cleaner
    DIFFERENCES
    Fix-diff         latest fixes 3 of your critical/high CVE(s), 0 still present
    Fixed            CVE-2026-1111 (critical, openssl → fixed in 3.3.2)
    Med/low          18 → 22  (count only — no CVE detail)
    Detail           per-CVE detail: critical/high only

  [2] FROM build
    Status           skipped — references build stage 'build'
```

> 📸 *Screenshot placeholder — add a real terminal capture of the `--dockerfile` panel here.*

The **DIFFERENCES** section is the fix-diff: it lists the **critical/high** CVEs that upgrading to
the latest digest would **fix**, the critical/high CVEs that would **still be present**, and a
`Med/low` line summarising how the medium/low/unknown counts move.

> **Per-CVE detail is critical/high only.** The named `Fixed` / `Still` CVE lists cover
> **critical and high** severities only. Medium, low and unknown findings are counted (and shown in
> the `Med/low` movement) but never listed individually — treat the "fixed by upgrading" list as a
> critical/high view, not the complete CVE set.

When the pinned digest has no data, or no digest is pinned, the stage simply shows the latest tracked
digest for the tag; when nothing is tracked, it says so rather than inventing a number.

### JSON output

Add `--json` to emit the whole inspection as a single object — ideal for failing a CI job when a
pinned base image has known critical/high vulnerabilities:

```bash
image-inspector --dockerfile ./Dockerfile --json
```

The payload has report-level metadata plus a `stages` array:

```json
{
  "dockerfile": "./Dockerfile",
  "generated_at": "2026-06-22T02:14:07+00:00",
  "data_source": "online",
  "scanner": { "name": "trivy", "version": "0.71.1", "db_updated_at": "2026-06-22T00:00:00+00:00" },
  "stage_count": 2,
  "stages": [
    {
      "index": 0,
      "from": "FROM python:3.13-slim@sha256:abc...",
      "raw": "python:3.13-slim@sha256:abc...",
      "image": "python",
      "tag": "3.13-slim",
      "alias": null,
      "reference": "python:3.13-slim",
      "references_stage": false,
      "status": "pinned_known",
      "note": null,
      "pinned": {
        "digest": "sha256:abc...",
        "vulnerabilities": { "critical": 1, "high": 3, "medium": 14, "low": 4, "unknown": 0, "total": 27, "scanned_at": "2026-06-22T02:14:07+00:00" }
      },
      "latest": {
        "digest": "sha256:205e60d0b78f024817...",
        "created": "2026-06-22T00:00:00+00:00",
        "vulnerabilities": { "critical": 0, "high": 1, "medium": 18, "low": 4, "unknown": 0, "total": 23, "scanned_at": "2026-06-22T02:14:07+00:00" }
      },
      "critical_high": {
        "detail_scope": "critical_high_only",
        "fixed": [ { "id": "CVE-2026-1111", "package": "openssl", "severity": "critical", "fixed_version": "3.3.2" } ],
        "still_present": []
      },
      "flags": { "has_data": true, "pinned_vulnerable": true, "latest_is_cleaner": true }
    }
  ]
}
```

Field notes:

- `status` is one of the per-stage statuses described above; `note` carries the reason a stage was
  `skipped` or `untracked`.
- `pinned` / `latest` each hold a `digest` and a full `vulnerabilities` block (all severities plus
  `total` and `scanned_at`); either `vulnerabilities` is `null` when that side has no scan data.
- `critical_high.detail_scope` is always `"critical_high_only"`, a reminder that the `fixed` and
  `still_present` CVE arrays are limited to critical/high. Each CVE entry is
  `{ id, package, severity, fixed_version }`.
- `flags` are convenience booleans for scripting: `has_data` (any counts available),
  `pinned_vulnerable` (the pinned digest has critical/high findings), and `latest_is_cleaner` (the
  latest digest has fewer critical+high findings than the pinned one).

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

## History, retention and "latest tracked digest"

The report stores more than just the current image for each tag — it keeps a short **per-tag digest
history**. Every tag (for example `python:3.13-slim`) tracks the digests that have appeared on it
over time, ordered newest-first by build date. Internally each entry is a compact `{d, t, c}` record:
the **d**igest, the build **t**ime, and the vulnerability **c**ounts.

This history is what makes the `--dockerfile` comparison work:

- The **head** (newest) entry of a tag's history is the **"latest tracked digest"** — the target the
  comparison upgrades toward. It is the freshest digest image-inspector has data for, not a live
  registry lookup.
- The older entries let the tool still recognise a **specific digest you pinned earlier**, so it can
  show you exactly which critical/high CVEs that pinned image carries versus the latest one.

To keep the dataset small, history is pruned by a deterministic **retention policy** when the nightly
report is regenerated:

- **Age:** a non-current digest is dropped once it has been superseded for more than **180 days**. The
  current (head) digest of a tag is the live image and is **never** aged out.
- **Depth:** each tag keeps at most **30** digests; older entries beyond that are trimmed.

Because of this, a digest you pinned long ago can eventually fall out of the retained history. When
that happens the `--dockerfile` view reports the stage as `pinned_unknown` and compares against the
tag's latest tracked digest instead — image-inspector never fabricates counts for a digest it no
longer has data for. The companion **critical/high CVE detail** (used for the fix-diff) lives in a
separate `details.json.gz` sidecar that is loaded **lazily**, only when you run `--dockerfile`, so the
normal picker stays fast.

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
