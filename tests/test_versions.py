"""Unit tests for tag parsing and version selection logic."""

from image_inspector.models import LANGUAGES_BY_KEY, Category, RegistryKind, VersionScheme
from image_inspector.versions import (
    PLAIN_VARIANT,
    is_ubuntu_lts,
    latest_calver_versions,
    latest_major_versions,
    latest_minor_versions,
    parse_semver,
    select_versions,
    tag_for_selection,
    variants_for_version,
)

TAGS = [
    "3.14.6",
    "3.13.14",
    "3.13.13",
    "3.12.13",
    "3.11.15",
    "3.10.20",
    "3.9.99",
    "3.13",
    "3",
    "latest",
    "3.13.14-slim",
    "3.13.14-alpine",
    "3.13.14-bookworm",
    "3.13.14-slim-bookworm",
]


def test_parse_semver_accepts_bare_versions():
    assert str(parse_semver("3.13.14")) == "3.13.14"


def test_parse_semver_rejects_non_semver():
    assert parse_semver("3.13") is None
    assert parse_semver("latest") is None
    assert parse_semver("3.13.14-slim") is None


def test_latest_minor_versions_picks_top_patch_per_minor():
    result = latest_minor_versions(TAGS, count=5)
    assert result == ["3.14.6", "3.13.14", "3.12.13", "3.11.15", "3.10.20"]


def test_latest_minor_versions_respects_count():
    assert latest_minor_versions(TAGS, count=2) == ["3.14.6", "3.13.14"]


def test_variants_for_version_lists_plain_first_then_sorted():
    variants = variants_for_version(TAGS, "3.13.14")
    assert variants[0] == PLAIN_VARIANT
    assert variants[1:] == ["alpine", "bookworm", "slim", "slim-bookworm"]


def test_variants_for_version_without_plain_tag():
    variants = variants_for_version(["1.2.3-slim", "1.2.3-alpine"], "1.2.3")
    assert PLAIN_VARIANT not in variants
    assert variants == ["alpine", "slim"]


def test_tag_for_selection():
    assert tag_for_selection("3.13.14", PLAIN_VARIANT) == "3.13.14"
    assert tag_for_selection("3.13.14", "slim") == "3.13.14-slim"


JAVA_TAGS = [
    "8",
    "11",
    "17",
    "21",
    "25",
    "26",
    "latest",
    "21-jdk",
    "21-jre",
    "21-jdk-noble",
    "21.0.5_11-jdk",
]


def test_latest_major_versions_numeric_desc():
    assert latest_major_versions(JAVA_TAGS, count=5) == ["26", "25", "21", "17", "11"]


def test_latest_major_versions_ignores_non_integer_tags():
    assert latest_major_versions(["21-jdk", "latest", "21.0.5_11-jdk"]) == []


def test_select_versions_dispatches_on_scheme():
    assert select_versions(JAVA_TAGS, VersionScheme.MAJOR, count=3) == ["26", "25", "21"]
    assert select_versions(TAGS, VersionScheme.SEMVER, count=2) == ["3.14.6", "3.13.14"]


def test_latest_minor_versions_empty_input():
    assert latest_minor_versions([]) == []
    assert latest_minor_versions(["latest", "3.13-slim"]) == []


def test_latest_minor_versions_count_exceeds_available():
    tags = ["3.14.6", "3.13.14"]
    assert latest_minor_versions(tags, count=10) == ["3.14.6", "3.13.14"]


def test_latest_major_versions_empty_input():
    assert latest_major_versions([]) == []
    assert latest_major_versions(["latest", "21-jdk"]) == []


def test_latest_major_versions_count_exceeds_available():
    tags = ["21", "17"]
    assert latest_major_versions(tags, count=10) == ["21", "17"]


def test_variants_reused_for_major_scheme():
    variants = variants_for_version(JAVA_TAGS, "21")
    assert variants[0] == PLAIN_VARIANT
    assert variants[1:] == ["jdk", "jdk-noble", "jre"]


def test_new_language_mappings():
    java = LANGUAGES_BY_KEY["java"]
    assert java.repository == "library/eclipse-temurin"
    assert java.scheme is VersionScheme.MAJOR
    assert java.image_name == "eclipse-temurin"

    rust = LANGUAGES_BY_KEY["rust"]
    assert rust.repository == "library/rust"
    assert rust.scheme is VersionScheme.SEMVER

    cpp = LANGUAGES_BY_KEY["cpp"]
    assert cpp.label == "C / C++"
    assert cpp.repository == "library/gcc"
    assert cpp.registry is RegistryKind.DOCKER_HUB


UBUNTU_TAGS = [
    "26.04",
    "25.10",
    "25.04",
    "24.10",
    "24.04",
    "23.10",
    "22.04",
    "latest",
    "rolling",
    "noble",
]


def test_latest_calver_versions_newest_first_preserving_zero():
    result = latest_calver_versions(UBUNTU_TAGS, count=5)
    assert result == ["26.04", "25.10", "25.04", "24.10", "24.04"]


def test_latest_calver_versions_ignores_non_calver_tags():
    assert latest_calver_versions(["latest", "noble", "24"], count=5) == []


def test_latest_calver_versions_empty_input():
    assert latest_calver_versions([]) == []
    assert latest_calver_versions(["latest", "noble"]) == []


def test_latest_calver_versions_count_exceeds_available():
    tags = ["26.04", "24.04"]
    assert latest_calver_versions(tags, count=10) == ["26.04", "24.04"]


def test_calver_roundtrip_tag_for_selection_variants_for_version():
    """Verify tag_for_selection and variants_for_version agree for CalVer tags."""
    ubuntu_tags = UBUNTU_TAGS
    for version in latest_calver_versions(ubuntu_tags, count=5):
        variants = variants_for_version(ubuntu_tags, version)
        for variant in variants:
            reconstructed = tag_for_selection(version, variant)
            assert reconstructed in ubuntu_tags, (
                f"Round-trip failed: version={version!r}, variant={variant!r}, "
                f"reconstructed={reconstructed!r} not in tags"
            )


def test_is_ubuntu_lts():
    assert is_ubuntu_lts("24.04") is True
    assert is_ubuntu_lts("22.04") is True
    assert is_ubuntu_lts("26.04") is True
    assert is_ubuntu_lts("25.10") is False
    assert is_ubuntu_lts("24.10") is False
    assert is_ubuntu_lts("23.04") is False
    assert is_ubuntu_lts("latest") is False


def test_select_versions_dispatches_calver():
    assert select_versions(UBUNTU_TAGS, VersionScheme.CALVER, count=3) == [
        "26.04",
        "25.10",
        "25.04",
    ]


def test_os_language_mappings():
    ubuntu = LANGUAGES_BY_KEY["ubuntu"]
    assert ubuntu.repository == "library/ubuntu"
    assert ubuntu.scheme is VersionScheme.CALVER
    assert ubuntu.category is Category.OS
    assert ubuntu.marks_lts is True

    debian = LANGUAGES_BY_KEY["debian"]
    assert debian.repository == "library/debian"
    assert debian.scheme is VersionScheme.MAJOR
    assert debian.category is Category.OS

    alpine = LANGUAGES_BY_KEY["alpine"]
    assert alpine.repository == "library/alpine"
    assert alpine.scheme is VersionScheme.SEMVER
    assert alpine.category is Category.OS
