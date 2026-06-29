# 🐳 image-inspector — select • inspect • pin

<p align="center">
  <img src="https://raw.githubusercontent.com/anmalkov/image-inspector/main/docs/assets/logo.png" alt="image-inspector" width="300">
</p>

<p align="center">
  <strong>A CLI for finding official container base images, showing precomputed vulnerability counts, and generating digest-pinned <code>FROM</code> lines — without pulling images, running Docker, or scanning locally.</strong>
</p>

<p align="center">
  <a href="https://github.com/anmalkov/image-inspector/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://img.shields.io/github/actions/workflow/status/anmalkov/image-inspector/ci.yml?branch=main&style=for-the-badge" alt="CI status"></a>
  <a href="https://github.com/anmalkov/image-inspector/releases"><img src="https://img.shields.io/github/v/release/anmalkov/image-inspector?style=for-the-badge" alt="Latest release"></a>
  <a href="https://pypi.org/project/base-image-inspector/"><img src="https://img.shields.io/pypi/v/base-image-inspector?style=for-the-badge" alt="PyPI version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License"></a>
</p>

---

## ⚡ Try it in 5 seconds

No install, no Docker daemon, no local scanner — just [uv](https://docs.astral.sh/uv/):

```bash
uvx --from base-image-inspector image-inspector
```

Pick a base image with the arrow keys and copy the digest-pinned `FROM` line. That's it.

<p align="center">
  <img src="https://raw.githubusercontent.com/anmalkov/image-inspector/main/docs/assets/screenshot.png" alt="image-inspector result panel showing a digest-pinned FROM line and vulnerability counts">
</p>

## Why this exists

| Tool | Great at | The gap it leaves |
|------|----------|-------------------|
| `docker pull` + `trivy scan` | Accurate, thorough scanning | Slower, and runs locally — you pull the image first |
| Renovate | Keeping base images up to date | Helps *after* you've already chosen a base image |
| **image-inspector** | **Choose + inspect + pin _before_ you write `FROM`** | Approximate counts from precomputed nightly data (fetched from GitHub Pages, bundled offline fallback), not a live scan |

## Who is this for?

Use **image-inspector** if you:

- write Dockerfiles often
- want reproducible base images
- want quick vulnerability context before choosing a base image
- don't want to pull images or run a scanner locally

---

## What is this?

When you write a `Dockerfile`, you start from a **base image** like `python:3.13` or `node:22`.
The problem: tags like `python:3.13` are **moving targets** — the image behind that tag changes over
time. So a build that works today might pull a different image tomorrow, and "it works on my machine"
quietly breaks.

**image-inspector** fixes that. You pick a language or OS, a version, and a variant — all with the
arrow keys — and it gives you a base image **pinned to an immutable digest** plus a
ready-to-paste `FROM` line:

```dockerfile
FROM python:3.13.14-slim@sha256:205e60d0b78f024817...
```

It also shows you, up front, **how many known security vulnerabilities** that image has, its size, and
when it was built — so you can choose a good base image with confidence.

> **What's that `@sha256:...` part?** It's the image's **digest** — a unique fingerprint of the exact
> image contents. Pinning to a digest means everyone who builds your `Dockerfile` gets the *identical*
> base image, every time. That's what makes a build reproducible.

Vulnerability counts come from precomputed nightly Trivy data — fetched from GitHub Pages
when online, with a copy bundled in the package as an offline fallback. Images are not pulled
or scanned locally at runtime. No Docker daemon or local scanner is required.

<p align="center">
  <img src="https://raw.githubusercontent.com/anmalkov/image-inspector/main/docs/assets/demo.gif" alt="image-inspector demo">
</p>

## Quick start

**1. Already tried it with `uvx`? Install it permanently** (pick whichever you have):

```bash
uv tool install base-image-inspector     # recommended
# or
pipx install base-image-inspector
# or
pip install base-image-inspector
```

> **Package vs. command:** the PyPI package is `base-image-inspector`, but the installed CLI command
> is `image-inspector`.

Prefer one-shot usage? Use [uv](https://docs.astral.sh/uv/):

```bash
uvx --from base-image-inspector image-inspector
```

**2. Run it:**

```bash
image-inspector
```

**3. Pick with the arrow keys** — language/OS → version → variant — and copy the `FROM` line it
prints. That's it. 🎉

New here and want the full walkthrough? See the **[Getting started guide](https://github.com/anmalkov/image-inspector/blob/main/docs/getting-started.md)**.

## Features

- 📌 **Digest pinning** — outputs a `name:tag@sha256:…` reference for reproducible builds.
- 🛡️ **Security at a glance** — critical / high / total vulnerability counts for the chosen image,
  from precomputed nightly Trivy data fetched from GitHub Pages (with a bundled offline fallback).
- 🧱 **Many ecosystems, one interface** — Python, .NET, Java, Go, Node, Rust, C/C++, plus Ubuntu,
  Debian and Alpine base images.
- 🔎 **Inspect an existing Dockerfile** — `--dockerfile <path>` compares each pinned `FROM`
  image against the latest tracked digest and shows which critical/high CVEs upgrading would fix.
- 🤖 **Automation-friendly** — `--json` for non-interactive use and `--plain` / `NO_COLOR` support.
- 🎨 **Modern UI** — branded banner, themed menus, spinners, and a syntax-highlighted result panel.
- ⌨️ **Arrow-key everything** — language, version, and variant are all pick-from-list menus. No typing.
- 📋 **Quick actions** — after a result, copy the `FROM` line or digest to your clipboard.

## Supported images

### Languages &amp; runtimes

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

Per-image details (Java feature releases, the `gcc` compiler image, Ubuntu LTS, Debian variants) are
covered in the [Getting started guide](https://github.com/anmalkov/image-inspector/blob/main/docs/getting-started.md#supported-images-in-detail).

## Examples

```bash
# Interactive — pick everything with the arrow keys:
image-inspector

# Non-interactive, machine-readable output for scripts/CI:
image-inspector --json -l ubuntu --version 24.04

# Inspect an existing Dockerfile — compare each FROM against the latest tracked digest:
image-inspector --dockerfile ./Dockerfile

# ...as machine-readable JSON for CI:
image-inspector --dockerfile ./Dockerfile --json
```

A `--json` run prints a single object describing the resolved image. For example:

```bash
image-inspector --json -l python --version 3.13 --variant slim
```

```json
{
  "source": "Docker Hub",
  "language": "python",
  "version": "3.13",
  "variant": "slim",
  "image": "python:3.13.14-slim",
  "pinned_reference": "python:3.13.14-slim@sha256:205e60d0b78f024817...",
  "digest": "sha256:205e60d0b78f024817...",
  "size_bytes": 44912345,
  "from_line": "FROM python:3.13.14-slim@sha256:205e60d0b78f024817...",
  "vulnerabilities": {
    "critical": 0,
    "high": 1,
    "total": 23,
    "scanned_at": "2026-06-22T02:14:07+00:00"
  },
  "scanner": { "name": "trivy", "version": "0.71.1", "db_updated_at": "2026-06-22T00:00:00+00:00" }
}
```

(Some fields are omitted above for brevity.) When no scan data exists for the image,
`vulnerabilities` is `null`.

The full list of flags lives in the [Getting started guide](https://github.com/anmalkov/image-inspector/blob/main/docs/getting-started.md#command-line-options).

## Inspect an existing Dockerfile

Already have a `Dockerfile`? Point image-inspector at it to see, for every `FROM` line, how the
**digest you pinned** compares to the **latest tracked digest** for that tag — and exactly which
critical/high CVEs upgrading would fix:

```bash
image-inspector --dockerfile ./Dockerfile
```

For each `FROM` stage it shows the pinned digest's vulnerability counts, the latest tracked
digest's counts (with a ready-to-paste `FROM` line), and a **differences** view. Sample output:

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

A few things to know about what you're seeing:

- **Per-CVE detail is critical/high only.** The `Fixed` / `Still` lists name individual
  **critical and high** CVEs. Medium, low and unknown findings are reflected in the counts and the
  `Med/low` movement line, but are never listed one by one — so the "fixed by upgrading" list is a
  critical/high view, not the full CVE set.
- **"Latest tracked digest"** is the most recently built digest image-inspector has data for on that
  tag (see [history & retention](#history--retention) below). It is not a live registry lookup — no
  images are pulled and nothing is scanned on your machine.
- **No data for a digest?** If the exact digest you pinned isn't tracked (e.g. it aged out, or the
  tag is brand-new), image-inspector doesn't guess — it falls back to showing the latest tracked
  digest for the tag, or reports the image/tag as not tracked. `FROM` lines that build on an earlier
  stage or depend on an unresolved `ARG` are skipped with a note.

For scripts and CI, add `--json` to get the same comparison as a single machine-readable object:

```bash
image-inspector --dockerfile ./Dockerfile --json
```

The [Getting started guide](https://github.com/anmalkov/image-inspector/blob/main/docs/getting-started.md#inspecting-a-dockerfile)
documents the full per-stage statuses and the JSON payload shape.

## Vulnerability data

The critical / high / total counts come from **precomputed nightly [Trivy](https://github.com/aquasecurity/trivy)
data**. Nothing is scanned locally at runtime — image-inspector doesn't run Trivy
on your machine, pull images, or talk to a scanner. That keeps it fast and means no Docker daemon or
scanner is required. A GitHub Actions workflow regenerates this data **nightly** and publishes it to
[GitHub Pages](https://anmalkov.github.io/image-inspector/report.json.gz). At runtime the tool is
**online-first**: it fetches that live report when online (short timeout, `ETag`-cached) and **falls
back to the copy bundled with the package when offline** or if the fetch fails. The **SECURITY**
panel's `Source` row shows which you're seeing (`online (latest)` vs `offline (bundled copy)`). Set
`IMAGE_INSPECTOR_OFFLINE=1` to force the bundled copy, or `IMAGE_INSPECTOR_REPORT_URL` to point at a
different report. Because the data is precomputed, counts reflect the most recent snapshot rather
than a live, on-the-spot scan.

### History & retention

The report keeps a short **per-tag digest history**, not just the current image. Each tag (e.g.
`python:3.13-slim`) tracks a list of the digests that have appeared on it over time, newest first.
The newest entry is the **"latest tracked digest"** the `--dockerfile` comparison upgrades toward,
and older entries let the tool still recognise a digest you pinned a while ago.

History is bounded so the dataset stays small: a non-current digest is dropped once it has been
superseded for more than **180 days**, and each tag keeps at most **30** digests. The current (head)
digest of a tag is never aged out. This is why a digest you pinned long ago may eventually show up as
"not tracked" — it has aged out of the retained history.

### Bundled format & critical/high sidecar

The data ships as a gzipped `report.json.gz` (the counts) plus a `details.json.gz` **sidecar** that
holds the deduplicated **critical/high CVE detail**. The sidecar is loaded **lazily** — only when
it's actually needed: when you run `--dockerfile` (for the fix-diff), and in the normal picker when a
selected image has at least one critical/high finding to list. A clean image, or a run that never
needs CVE detail, never fetches it, so the common path stays fast. Both files are fetched from GitHub
Pages when online, with copies bundled in the package as an offline fallback.

## Limitations

- Vulnerability counts come from the precomputed nightly dataset (online from GitHub Pages, or the bundled offline fallback), not a live scan.
- Counts are for the selected base image only, not your final application image.
- Digest pinning improves reproducibility, but you still need a process for updating pinned
  images.
- Only selected official images are supported.

## Why not just use Trivy, Docker Scout, or Renovate?

image-inspector is not a replacement for full image scanning, Docker Scout, Trivy, or
dependency automation tools like Renovate.

It is meant for the moment before you write a `FROM` line: choosing among official base
images, seeing approximate vulnerability counts, and pinning the exact digest without
pulling images locally or running a scanner.

You should still scan your final built image in CI.

## Documentation

- 📖 **[Getting started guide](https://github.com/anmalkov/image-inspector/blob/main/docs/getting-started.md)** — full usage, all flags, JSON output, and
  vulnerability data.
- 🛠️ **[Development guide](https://github.com/anmalkov/image-inspector/blob/main/docs/development.md)** — set up locally, run the tool from source, lint,
  type-check, and test.
- 🚀 **[Releasing guide](https://github.com/anmalkov/image-inspector/blob/main/docs/releasing.md)** — how releases are built and published.

## Community & support

- Bug reports and feature requests: [GitHub Issues](https://github.com/anmalkov/image-inspector/issues)
- Questions and ideas: [GitHub Discussions](https://github.com/anmalkov/image-inspector/discussions)
- Quick chat: [Discord](https://discord.gg/vnAh9Cqyw)

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](https://github.com/anmalkov/image-inspector/blob/main/CONTRIBUTING.md) for the branch/PR flow,
local checks, and where to ask questions.

## License

Released under the [MIT License](https://github.com/anmalkov/image-inspector/blob/main/LICENSE).
