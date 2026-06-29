"""Tests for the Dockerfile pinned-vs-latest inspection logic and ``--dockerfile`` CLI."""

import pytest

from image_inspector import cli, ui
from image_inspector.inspection import (
    StageStatus,
    inspect_dockerfile,
    inspect_stage,
    normalize_image,
)
from image_inspector.report import DetailsReport, VulnerabilityReport

# Stripped digests as stored in the report/details indices.
_PINNED = "pinneddigest"
_LATEST = "latestdigest"
_PINNED_REF = f"sha256:{_PINNED}"


def _report() -> VulnerabilityReport:
    """A report tracking ``python:3.13.14-slim`` with a latest head + an older pinned digest."""
    payload = {
        "schema_version": 3,
        "generated_at": "2026-06-15T02:00:00Z",
        "tags": {
            "python:3.13.14-slim": {
                "history": [
                    {"d": _LATEST, "t": "2026-06-14T07:00:00Z", "c": [0, 1, 2, 3, 0]},
                    {"d": _PINNED, "t": "2026-06-01T07:00:00Z", "c": [2, 5, 10, 20, 3]},
                ]
            }
        },
    }
    return VulnerabilityReport.from_dict(payload)


def _details() -> DetailsReport:
    """Details where the pinned digest has CVE-A/B/C and the latest only keeps CVE-B."""
    payload = {
        "schema_version": 3,
        "vulns": [
            {"id": "CVE-A", "pkg": "openssl", "sev": "C", "fix": "3.3.2"},
            {"id": "CVE-B", "pkg": "zlib", "sev": "H", "fix": None},
            {"id": "CVE-C", "pkg": "glibc", "sev": "C", "fix": "2.40"},
        ],
        "digests": {_PINNED: [0, 1, 2], _LATEST: [1]},
    }
    return DetailsReport.from_dict(payload)


def _only(text: str):
    stages = inspect_dockerfile(text, _report(), _details())
    assert len(stages) == 1
    return stages[0]


# --- normalize_image ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("python", "python"),
        ("library/python", "python"),
        ("docker.io/library/python", "python"),
        ("index.docker.io/library/python", "python"),
        ("mcr.microsoft.com/dotnet/sdk", "mcr.microsoft.com/dotnet/sdk"),
        ("ghcr.io/owner/app", "ghcr.io/owner/app"),
    ],
)
def test_normalize_image(raw: str, expected: str) -> None:
    assert normalize_image(raw) == expected


# --- report.latest_digest_for_tag ----------------------------------------------------------


def test_latest_digest_for_tag_returns_head_digest() -> None:
    report = _report()
    assert report.latest_digest_for_tag("python:3.13.14-slim") == _LATEST
    assert report.latest_digest_for_tag("python:unknown") is None
    assert report.latest_digest_for_tag(None) is None


# --- inspect_stage statuses ----------------------------------------------------------------


def test_pinned_and_known() -> None:
    inspection = _only(f"FROM python:3.13.14-slim@{_PINNED_REF}")
    assert inspection.status is StageStatus.PINNED_KNOWN
    assert inspection.reference == "python:3.13.14-slim"
    assert inspection.pinned_counts is not None
    assert inspection.pinned_counts.critical == 2
    assert inspection.pinned_counts.high == 5
    assert inspection.latest_counts is not None
    assert inspection.latest_counts.high == 1
    # fix-diff: CVE-A and CVE-C fixed by upgrading, CVE-B still present.
    assert {v.id for v in inspection.fixed} == {"CVE-A", "CVE-C"}
    assert {v.id for v in inspection.still_present} == {"CVE-B"}


def test_fix_diff_is_critical_first_then_id_sorted() -> None:
    inspection = _only(f"FROM python:3.13.14-slim@{_PINNED_REF}")
    # Both fixed CVEs are critical, so they sort by id: CVE-A before CVE-C.
    assert [v.id for v in inspection.fixed] == ["CVE-A", "CVE-C"]


def test_pinned_but_unknown_falls_back_to_latest() -> None:
    inspection = _only("FROM python:3.13.14-slim@sha256:notindata")
    assert inspection.status is StageStatus.PINNED_UNKNOWN
    assert inspection.pinned_counts is None
    assert inspection.latest_counts is not None
    assert inspection.latest_counts.high == 1
    assert inspection.fixed == ()
    assert inspection.still_present == ()
    assert inspection.note is None


def test_tag_known_no_digest() -> None:
    inspection = _only("FROM python:3.13.14-slim")
    assert inspection.status is StageStatus.TAG_KNOWN
    assert inspection.pinned_counts is None
    assert inspection.latest_counts is not None
    assert inspection.latest_counts.high == 1


def test_fully_unknown() -> None:
    inspection = _only("FROM alpine:3.18")
    assert inspection.status is StageStatus.UNTRACKED
    assert inspection.pinned_counts is None
    assert inspection.latest_counts is None
    assert inspection.note is not None


def test_pinned_known_but_tag_untracked_has_no_fix_diff() -> None:
    # Pin a known digest but reference a tag with no tracked latest head.
    inspection = _only(f"FROM python:9.9.9@{_PINNED_REF}")
    assert inspection.status is StageStatus.PINNED_KNOWN
    assert inspection.pinned_counts is not None
    assert inspection.latest_counts is None
    assert inspection.fixed == ()
    assert inspection.still_present == ()


def test_docker_hub_prefix_is_normalized_for_lookup() -> None:
    inspection = _only("FROM docker.io/library/python:3.13.14-slim")
    assert inspection.status is StageStatus.TAG_KNOWN
    assert inspection.reference == "python:3.13.14-slim"


# --- skips ---------------------------------------------------------------------------------


def test_stage_alias_reference_is_skipped() -> None:
    stages = inspect_dockerfile(
        "FROM python:3.13.14-slim AS build\nFROM build\n", _report(), _details()
    )
    assert len(stages) == 2
    assert stages[0].status is StageStatus.TAG_KNOWN
    assert stages[1].status is StageStatus.SKIPPED
    assert stages[1].note is not None
    assert "build stage" in stages[1].note


def test_unresolved_arg_is_skipped() -> None:
    inspection = _only("FROM python:${PYVER}")
    assert inspection.status is StageStatus.SKIPPED
    assert inspection.note is not None
    assert "ARG" in inspection.note
    assert "PYVER" in inspection.note


# --- multi-stage ---------------------------------------------------------------------------


def test_multi_stage_mixed_statuses_in_order() -> None:
    text = (
        f"FROM python:3.13.14-slim@{_PINNED_REF} AS build\n"
        "FROM python:3.13.14-slim\n"
        "FROM alpine:3.18\n"
        "FROM build\n"
    )
    stages = inspect_dockerfile(text, _report(), _details())
    assert [s.status for s in stages] == [
        StageStatus.PINNED_KNOWN,
        StageStatus.TAG_KNOWN,
        StageStatus.UNTRACKED,
        StageStatus.SKIPPED,
    ]


# --- inspect_stage directly (no parse) -----------------------------------------------------


def test_inspect_stage_handles_empty_image() -> None:
    from image_inspector.dockerfile import FromStage

    inspection = inspect_stage(FromStage(index=0, raw=""), _report(), _details())
    assert inspection.status is StageStatus.SKIPPED


# --- CLI --dockerfile ----------------------------------------------------------------------


def test_cli_dockerfile_end_to_end(monkeypatch, tmp_path, capsys) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(f"FROM python:3.13.14-slim@{_PINNED_REF}\n", encoding="utf-8")

    monkeypatch.setattr(cli, "load_report", _report)
    monkeypatch.setattr(cli, "load_details", _details)

    code = cli.main(["--dockerfile", str(dockerfile), "--plain"])
    assert code == 0

    out = capsys.readouterr().out
    assert "FROM python:3.13.14-slim" in out
    assert "Vulnerabilities" in out
    assert "LATEST DIGEST" in out
    assert "Fix-diff" in out
    assert "CVE-A" in out
    assert "CVE-B" in out


def test_cli_dockerfile_missing_file_errors(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_report", _report)
    monkeypatch.setattr(cli, "load_details", _details)
    code = cli.main(["--dockerfile", str(tmp_path / "nope"), "--plain"])
    assert code == 2


def test_render_dockerfile_inspection_no_stages(capsys) -> None:
    ui.configure(plain=True)
    ui.render_dockerfile_inspection("Dockerfile", [])
    out = capsys.readouterr().out
    assert "0 FROM instruction(s)" in out
    assert "No FROM instructions found." in out
