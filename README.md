# 🐳 image-inspector - Images, Digests & Vulnerabilities

<p align="center">
  <img src="https://raw.githubusercontent.com/anmalkov/image-inspector/main/docs/assets/logo.png" alt="image-inspector" width="250">
</p>

**Image inspector** is a modern, interactive terminal tool for selecting an **official container
image** and pinning it by digest for reproducible Docker builds.

Pick a language, pick a version, pick a variant — entirely with the arrow keys —
and `image-inspector` shows you the exact image reference, its creation date, its
compressed size, and
its SHA256 digest, plus a ready-to-paste `FROM` line.

```
FROM python:3.13.14-slim@sha256:205e60d0b78f024817...
```

## Features

- **Arrow-key everything** — language, version, and variant are all pick-from-list
  menus (`questionary`). No typing required. The first menu is **grouped** into
  "Languages & runtimes" and "OS base images" for easy scanning.
- **Latest 5 minor versions** — shows the newest patch of each of the 5 most recent
  minor releases (e.g. `3.14.x`, `3.13.x`, …); Java/Debian instead list the latest
  feature/major releases (e.g. `26`, `25`, `21`, …) and Ubuntu lists the 5 newest
  calendar releases (e.g. `26.04`, `25.10`, …) with **LTS** releases marked.
- **Variant aware** — choose `slim`, `alpine`, `bookworm`, `jdk`/`jre`, etc.
- **Digest pinning** — outputs a `name:tag@sha256:…` reference for reproducible
  builds.
- **Size shown** — the compressed download size of the `linux/amd64` image.
- **Sectioned result panel** — the resolved image is grouped into **SELECTED**,
  **IMAGE**, **SECURITY** and **DOCKERFILE** sections so it's easy to scan.
- **Vulnerability counts** — the SECURITY section shows **critical / high / total**
  vulnerabilities for the selected image, when it was scanned, and the Trivy
  version + DB date behind it — sourced from a nightly Trivy scan that ships with
  the tool.
- **Multi-registry** — Python, Java, Go, Node, Rust, C/C++ and the OS base images
  (Ubuntu, Debian, Alpine) come from Docker Hub; **.NET** comes from Microsoft
  Container Registry (MCR), all behind one interface.
- **Modern UI** — branded banner, themed menus, animated spinners, and a
  syntax-highlighted result panel (`rich` + `pyfiglet`).
- **Automation-friendly** — `--plain` (uncolored) and `--json` (non-interactive)
  output modes, plus `NO_COLOR` support.
- **Quick actions** — after a result, copy the `FROM` line or digest to your
  clipboard (OSC 52), start a new selection, or exit.

## Supported images

### Languages & runtimes

| Language | Registry | Repository | Versioning |
|----------|----------|------------|------------|
| Python   | Docker Hub | `library/python` | semver (latest 5 minors) |
| .NET     | MCR | `mcr.microsoft.com/dotnet/sdk` | semver (latest 5 minors) |
| Java     | Docker Hub | `library/eclipse-temurin` | feature release (8 / 11 / 17 / 21 / 25 / 26) |
| Go       | Docker Hub | `library/golang` | semver (latest minors) |
| Node.js  | Docker Hub | `library/node` | semver (latest 5 minors) |
| Rust     | Docker Hub | `library/rust` | semver (latest 5 minors) |
| C / C++  | Docker Hub | `library/gcc` | semver (latest 5 minors) |

### OS base images

| Image  | Registry | Repository | Versioning |
|--------|----------|------------|------------|
| Ubuntu | Docker Hub | `library/ubuntu` | calver `YY.MM` (latest 5 releases, LTS marked) |
| Debian | Docker Hub | `library/debian` | major (11 / 12 / 13) + `-slim` variant |
| Alpine | Docker Hub | `library/alpine` | semver (latest 5 minors) |

**Notes:**

- **Java** uses the Docker Official OpenJDK image (`eclipse-temurin`), which is
  versioned by *feature release* rather than `X.Y.Z`. You pick a feature version
  (e.g. `21`) and a variant (`jdk`, `jre`, `jdk-noble`, `ubi9-minimal`, …).
- **C / C++** uses the official `gcc` image — a *compiler / build* base. You'll
  typically multi-stage from it into a slim runtime (e.g. `debian:*-slim` or
  distroless). There is no official `clang` image.
- **Ubuntu** is versioned by calendar release (`YY.MM`). The picker shows the 5
  newest releases including interim ones and tags **LTS** releases (April of an
  even year, e.g. `24.04`, `22.04`) so you can tell them apart from interim
  releases (e.g. `25.10`).
- **Debian** images are tagged by major release (`11`, `12`, `13`); pick `(none)`
  for the full image or `slim` for the smaller variant.

## Requirements

- Python **3.13+**
- [`uv`](https://docs.astral.sh/uv/)

## Install & run

```bash
uv sync          # create the venv and install dependencies
uv run image-inspector
```

You can also run it as a module:

```bash
uv run python -m image_inspector
```

### Command-line options

```bash
uv run image-inspector --help
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

```bash
# Non-interactive, machine-readable output for automation:
uv run image-inspector --json -l ubuntu --version 24.04 --variant '(none)'
```

After a result, an interactive action menu lets you `[f]` copy the `FROM` line,
`[d]` copy the digest (both via the OSC 52 clipboard escape), `[n]` start a new
selection, or press `[enter]` to exit.

## Vulnerability scanning

When you resolve an image, the result panel's **SECURITY** section shows how many
vulnerabilities it has — **critical**, **high** and **total** — the date the scan
was taken, and the scan source (the Trivy version plus the vulnerability-DB
update date, e.g. `Trivy v0.71.1 · DB Jun 14, 2026`).

These counts come from a JSON report (`src/image_inspector/data/report.json`)
that ships with the tool, so the interactive picker stays fast and needs no
Docker or Trivy on your machine. The report is regenerated **nightly** by a
GitHub Actions workflow that runs [Trivy](https://trivy.dev/) against every
selectable image (all versions and variants) and commits the refreshed report
back to the repository. The report header records the Trivy version and DB date
once; `--json` output surfaces them in a `scanner` block alongside the flat
`vulnerabilities` counts.

The report is keyed by the image's immutable **digest**, so the counts always
match the exact `name:tag@sha256:…` reference the tool pins. If an image isn't in
the report yet (e.g. a brand-new tag), the panel shows `no scan data` rather than
guessing.

### Running a scan yourself

The scanner is a separate entry point in this repo. You need
[Trivy](https://trivy.dev/) installed and on your `PATH`:

```bash
uv run image-inspector-scan                # scan every image, writes packaged data/report.json
uv run image-inspector-scan -l alpine      # only scan Alpine (repeatable: -l python -l go)
uv run image-inspector-scan -o report.json # write somewhere else
```

`--language`/`-l` accepts an image key (`python`, `dotnet`, `java`, `go`, `node`,
`rust`, `cpp`, `ubuntu`, `debian`, `alpine`) and may be repeated; omit it to scan
everything.

The nightly workflow uses this to **fan out one scan per language in a matrix**,
then combines the per-language reports into a single `report.json` with
`image-inspector-merge`:

```bash
uv run image-inspector-merge report-python.json report-alpine.json \
  -o src/image_inspector/data/report.json
```

`image-inspector-merge` takes any number of partial reports and unions their
images by digest, so parallel matrix jobs still produce one combined report.

## How it works

1. Pick a language/runtime.
2. The tool queries the matching registry and lists the latest patch of the 5
   newest minor versions.
3. Pick a version, then pick a variant.
4. It resolves the concrete tag to a digest, creation date and compressed size,
   then prints the pinned Dockerfile reference.

## Development

```bash
uv run pytest        # run the test suite
uv run ruff check .  # lint
uv run ruff format . # format
uv run mypy src      # type-check
```

See [docs/development.md](docs/development.md) for full setup instructions (prerequisites, dev
environment, running locally, and quality checks), and [docs/releasing.md](docs/releasing.md) for how
to publish a new release.

### Project layout

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
