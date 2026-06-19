# 🐳 image-inspector - select • inspect • pin

<p align="center">
  <img src="https://raw.githubusercontent.com/anmalkov/image-inspector/main/docs/assets/logo.png" alt="image-inspector" width="300">
</p>

<p align="center">
  <strong>Find an official container base image, check its known vulnerabilities, and pin it to an exact digest in seconds.</strong>
</p>

<p align="center">
  <a href="https://github.com/anmalkov/image-inspector/actions/workflows/ci.yml?query=branch%3Amain"><img src="https://img.shields.io/github/actions/workflow/status/anmalkov/image-inspector/ci.yml?branch=main&style=for-the-badge" alt="CI status"></a>
  <a href="https://github.com/anmalkov/image-inspector/releases"><img src="https://img.shields.io/github/v/release/anmalkov/image-inspector?include_prereleases&style=for-the-badge" alt="Latest release"></a>
  <a href="https://pypi.org/project/base-image-inspector/"><img src="https://img.shields.io/pypi/v/base-image-inspector?style=for-the-badge" alt="PyPI version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License"></a>
  <a href="https://discord.gg/bQSu89SU2"><img src="https://img.shields.io/badge/Discord-Join-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
</p>

---

## What is this?

When you write a `Dockerfile`, you start from a **base image** like `python:3.13` or `node:22`.
The problem: tags like `python:3.13` are **moving targets** — the image behind that tag changes over
time. So a build that works today might pull a different image tomorrow, and "it works on my machine"
quietly breaks.

**image-inspector** fixes that. You pick a language or OS, a version, and a variant — all with the
arrow keys — and it gives you a base image **pinned to an exact, unchangeable version** plus a
ready-to-paste `FROM` line:

```dockerfile
FROM python:3.13.14-slim@sha256:205e60d0b78f024817...
```

It also shows you, up front, **how many known security vulnerabilities** that image has, its size, and
when it was built — so you can choose a good base image with confidence.

> **What's that `@sha256:...` part?** It's the image's **digest** — a unique fingerprint of the exact
> image contents. Pinning to a digest means everyone who builds your `Dockerfile` gets the *identical*
> base image, every time. That's what makes a build reproducible.

You don't need Docker or any scanner installed to use it.

<p align="center">
  <img src="https://raw.githubusercontent.com/anmalkov/image-inspector/main/docs/assets/demo.gif" alt="image-inspector demo">
</p>

## Quick start

**1. Install it** (pick whichever you have):

```bash
uv tool install base-image-inspector     # recommended
# or
pipx install base-image-inspector
# or
pip install base-image-inspector
```

**2. Run it:**

```bash
image-inspector
```

**3. Pick with the arrow keys** — language/OS → version → variant — and copy the `FROM` line it
prints. That's it. 🎉

New here and want the full walkthrough? See the **[Getting started guide](docs/getting-started.md)**.

## Features

- 📌 **Digest pinning** — outputs a `name:tag@sha256:…` reference for reproducible builds.
- 🛡️ **Security at a glance** — critical / high / total vulnerability counts for the chosen image,
  from a nightly Trivy scan that ships with the tool.
- 🧱 **Many ecosystems, one interface** — Python, .NET, Java, Go, Node, Rust, C/C++, plus Ubuntu,
  Debian and Alpine base images.
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
covered in the [Getting started guide](docs/getting-started.md#supported-images-in-detail).

## Examples

```bash
# Interactive — pick everything with the arrow keys:
image-inspector

# Non-interactive, machine-readable output for scripts/CI:
image-inspector --json -l ubuntu --version 24.04'
```

The full list of flags lives in the [Getting started guide](docs/getting-started.md#command-line-options).

## Documentation

- 📖 **[Getting started guide](docs/getting-started.md)** — full usage, all flags, JSON output, and
  vulnerability scanning.
- 🛠️ **[Development guide](docs/development.md)** — set up locally, run the tool from source, lint,
  type-check, and test.
- 🚀 **[Releasing guide](docs/releasing.md)** — how releases are built and published.

## 💬 Community

Come hang out on **[Discord](https://discord.gg/bQSu89SU2)** — it's the best place to
ask for help, share feedback, suggest features, or just say hi. We're a small,
growing community and would love to have you.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the branch/PR flow,
local checks, and where to ask questions.

## License

Released under the [MIT License](LICENSE).
