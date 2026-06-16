"""Data models and the language -> registry mapping."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .report import ImageVulnerabilities


class RegistryKind(StrEnum):
    """Which registry backend a language's images live on."""

    DOCKER_HUB = "docker_hub"
    MCR = "mcr"


class VersionScheme(StrEnum):
    """How a language's versions are laid out in its image tags."""

    # Bare ``X.Y.Z`` tags grouped by minor (python, go, node, rust, gcc, dotnet).
    SEMVER = "semver"
    # Bare integer feature-release tags (java / eclipse-temurin: 8, 11, 17, 21...).
    MAJOR = "major"
    # Calendar ``YY.MM`` release tags (ubuntu: 24.04, 22.04, ...).
    CALVER = "calver"


class Category(StrEnum):
    """High-level grouping used to organise the selection menu."""

    LANGUAGE = "language"
    OS = "os"


@dataclass(frozen=True)
class Language:
    """A selectable language/runtime and where to find its official images."""

    key: str
    label: str
    registry: RegistryKind
    repository: str
    scheme: VersionScheme = VersionScheme.SEMVER
    category: Category = Category.LANGUAGE
    marks_lts: bool = False

    @property
    def image_name(self) -> str:
        """The image name as it appears in a Dockerfile ``FROM``.

        Docker Hub official images drop the ``library/`` prefix, while MCR
        images use their fully qualified ``mcr.microsoft.com/...`` name.
        """
        if self.registry is RegistryKind.DOCKER_HUB:
            return self.repository.removeprefix("library/")
        return f"mcr.microsoft.com/{self.repository}"


# Official image locations. .NET images are published to Microsoft Container
# Registry (MCR), not Docker Hub; everything else is a Docker Hub library image.
# Java (eclipse-temurin) is versioned by feature release, so it uses the MAJOR
# scheme; the C/C++ entry uses the official gcc compiler/build image. OS base
# images (ubuntu/debian/alpine) form a second menu category.
LANGUAGES: tuple[Language, ...] = (
    Language("python", "Python", RegistryKind.DOCKER_HUB, "library/python"),
    Language("dotnet", ".NET", RegistryKind.MCR, "dotnet/sdk"),
    Language(
        "java", "Java", RegistryKind.DOCKER_HUB, "library/eclipse-temurin", VersionScheme.MAJOR
    ),
    Language("go", "Go", RegistryKind.DOCKER_HUB, "library/golang"),
    Language("node", "Node.js", RegistryKind.DOCKER_HUB, "library/node"),
    Language("rust", "Rust", RegistryKind.DOCKER_HUB, "library/rust"),
    Language("cpp", "C / C++", RegistryKind.DOCKER_HUB, "library/gcc"),
    Language(
        "ubuntu",
        "Ubuntu",
        RegistryKind.DOCKER_HUB,
        "library/ubuntu",
        VersionScheme.CALVER,
        Category.OS,
        marks_lts=True,
    ),
    Language(
        "debian",
        "Debian",
        RegistryKind.DOCKER_HUB,
        "library/debian",
        VersionScheme.MAJOR,
        Category.OS,
    ),
    Language(
        "alpine",
        "Alpine",
        RegistryKind.DOCKER_HUB,
        "library/alpine",
        VersionScheme.SEMVER,
        Category.OS,
    ),
)

LANGUAGES_BY_KEY: dict[str, Language] = {lang.key: lang for lang in LANGUAGES}


@dataclass(frozen=True)
class ImageTag:
    """A concrete registry tag with its digest and last-updated timestamp."""

    name: str
    digest: str
    last_updated: datetime | None
    size: int | None = None


@dataclass(frozen=True)
class ResolvedImage:
    """The final image the user selected, ready to show in a Dockerfile."""

    language: Language
    tag: str
    digest: str
    created: datetime | None
    size: int | None = None
    vulnerabilities: ImageVulnerabilities | None = None

    @property
    def reference(self) -> str:
        """Plain ``name:tag`` reference."""
        return f"{self.language.image_name}:{self.tag}"

    @property
    def pinned_reference(self) -> str:
        """Digest-pinned ``name:tag@sha256:...`` reference."""
        return f"{self.reference}@{self.digest}"
