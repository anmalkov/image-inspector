"""Tests for the vulnerability report loader."""

from datetime import UTC, datetime

from image_inspector.report import (
    ImageVulnerabilities,
    VulnerabilityReport,
    load_report,
)

_SAMPLE = {
    "schema_version": 1,
    "generated_at": "2026-06-15T02:00:00Z",
    "trivy_version": "0.58.0",
    "images": {
        "sha256:abc": {
            "reference": "python:3.13.14-slim",
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "unknown": 0,
            "total": 10,
            "scanned_at": "2026-06-15T02:03:11Z",
        }
    },
}


def test_from_dict_parses_metadata_and_images():
    report = VulnerabilityReport.from_dict(_SAMPLE)
    assert report.trivy_version == "0.58.0"
    assert report.generated_at == datetime(2026, 6, 15, 2, 0, 0, tzinfo=UTC)
    vulns = report.lookup("sha256:abc")
    assert vulns == ImageVulnerabilities(
        critical=1,
        high=2,
        medium=3,
        low=4,
        unknown=0,
        total=10,
        scanned_at=datetime(2026, 6, 15, 2, 3, 11, tzinfo=UTC),
    )


def test_lookup_missing_or_none_digest_returns_none():
    report = VulnerabilityReport.from_dict(_SAMPLE)
    assert report.lookup("sha256:does-not-exist") is None
    assert report.lookup(None) is None


def test_empty_report_has_no_images():
    report = VulnerabilityReport.empty()
    assert report.images == {}
    assert report.lookup("sha256:abc") is None


def test_load_report_returns_report_object():
    # The packaged report.json ships empty until the first nightly scan.
    report = load_report()
    assert isinstance(report, VulnerabilityReport)
    assert isinstance(report.images, dict)
