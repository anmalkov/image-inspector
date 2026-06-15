"""Tag parsing: pick the latest 5 minor versions and their variants."""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from .models import VersionScheme

# Matches a bare semantic version tag like "3.13.1" or "1.23.4" (no suffix).
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Matches a bare integer feature-release tag like "21" (Java / eclipse-temurin).
_MAJOR_RE = re.compile(r"^\d+$")

# Matches a calendar ``YY.MM`` release tag like "24.04" (Ubuntu).
_CALVER_RE = re.compile(r"^\d+\.\d+$")

# Sentinel label for the plain, suffix-less variant.
PLAIN_VARIANT = "(none)"


def parse_semver(name: str) -> Version | None:
    """Return a :class:`Version` for a bare ``X.Y.Z`` tag, else ``None``."""
    if not _SEMVER_RE.match(name):
        return None
    try:
        return Version(name)
    except InvalidVersion:
        return None


def latest_minor_versions(tag_names: list[str], count: int = 5) -> list[str]:
    """Return the latest patch of each of the ``count`` newest minor versions.

    Given all tag names, keep bare ``X.Y.Z`` tags, group them by
    ``(major, minor)``, take the highest patch in each group, then return the
    ``count`` newest such versions (newest first) as plain strings.
    """
    best_per_minor: dict[tuple[int, int], Version] = {}
    for name in tag_names:
        version = parse_semver(name)
        if version is None:
            continue
        key = (version.major, version.minor)
        current = best_per_minor.get(key)
        if current is None or version > current:
            best_per_minor[key] = version

    ordered = sorted(best_per_minor.values(), reverse=True)
    return [str(version) for version in ordered[:count]]


def latest_major_versions(tag_names: list[str], count: int = 5) -> list[str]:
    """Return the ``count`` newest bare integer (feature-release) tags.

    Used for languages like Java whose images are tagged by feature release
    (``8``, ``11``, ``17``, ``21`` ...) rather than full semantic versions.
    """
    majors = {int(name) for name in tag_names if _MAJOR_RE.match(name)}
    ordered = sorted(majors, reverse=True)
    return [str(major) for major in ordered[:count]]


def latest_calver_versions(tag_names: list[str], count: int = 5) -> list[str]:
    """Return the ``count`` newest calendar ``YY.MM`` tags (newest first).

    Used for Ubuntu, whose images are tagged by calendar release (``24.04``,
    ``22.04`` ...). Original tag strings are preserved so the zero in ``24.04``
    is kept; ordering is by parsed version.
    """
    calvers = {name for name in tag_names if _CALVER_RE.match(name)}
    ordered = sorted(calvers, key=Version, reverse=True)
    return ordered[:count]


def is_ubuntu_lts(version: str) -> bool:
    """Return ``True`` for an Ubuntu LTS release (April of an even year)."""
    if not _CALVER_RE.match(version):
        return False
    year_str, month_str = version.split(".")
    return month_str == "04" and int(year_str) % 2 == 0


def select_versions(tag_names: list[str], scheme: VersionScheme, count: int = 5) -> list[str]:
    """Return selectable versions for a language according to its scheme."""
    if scheme is VersionScheme.MAJOR:
        return latest_major_versions(tag_names, count=count)
    if scheme is VersionScheme.CALVER:
        return latest_calver_versions(tag_names, count=count)
    return latest_minor_versions(tag_names, count=count)


def variants_for_version(tag_names: list[str], version: str) -> list[str]:
    """Return selectable variant labels for a chosen ``version``.

    The plain tag (``version`` itself) is represented by :data:`PLAIN_VARIANT`
    and always comes first; remaining variants are the sorted suffixes of tags
    shaped like ``{version}-{suffix}``.
    """
    prefix = f"{version}-"
    has_plain = False
    suffixes: set[str] = set()
    for name in tag_names:
        if name == version:
            has_plain = True
        elif name.startswith(prefix):
            suffixes.add(name[len(prefix) :])

    result: list[str] = []
    if has_plain:
        result.append(PLAIN_VARIANT)
    result.extend(sorted(suffixes))
    return result


def tag_for_selection(version: str, variant: str) -> str:
    """Combine a version and variant label into a concrete tag name."""
    if variant == PLAIN_VARIANT:
        return version
    return f"{version}-{variant}"
