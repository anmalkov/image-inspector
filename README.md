# image-inspector

A modern, interactive terminal tool for picking an **official container base
image** and pinning it by digest for your Dockerfile.

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
- **Multi-registry** — Python, Java, Go, Node, Rust, C/C++ and the OS base images
  (Ubuntu, Debian, Alpine) come from Docker Hub; **.NET** comes from Microsoft
  Container Registry (MCR), all behind one interface.
- **Modern UI** — branded banner, themed menus, animated spinners, and a
  syntax-highlighted result panel (`rich` + `pyfiglet`).

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
```

### Project layout

```
src/image_inspector/
  cli.py        # entry point + flow orchestration
  models.py     # dataclasses + language -> registry mapping
  registry.py   # RegistryProvider protocol + Docker Hub & MCR clients
  versions.py   # tag parsing, version-scheme selection (semver/major), variants
  ui.py         # theme, banner, prompts, spinners, result panel
```
