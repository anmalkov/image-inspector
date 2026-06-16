"""Unit tests for UI helpers."""

from datetime import UTC, datetime

from image_inspector.report import ImageVulnerabilities
from image_inspector.ui import format_size, format_vulnerabilities


def test_format_size_units():
    assert format_size(None) == "unknown"
    assert format_size(0) == "0 B"
    assert format_size(512) == "512 B"
    assert format_size(1024) == "1.0 KB"
    assert format_size(20393993) == "19.4 MB"
    assert format_size(3 * 1024**3) == "3.0 GB"


def test_format_vulnerabilities_none():
    assert format_vulnerabilities(None).plain == "no scan data"


def test_format_vulnerabilities_counts():
    vulns = ImageVulnerabilities(
        critical=1,
        high=2,
        total=10,
        scanned_at=datetime(2026, 6, 15, tzinfo=UTC),
    )
    text = format_vulnerabilities(vulns)
    assert text.plain == "Critical: 1  ·  High: 2  ·  Total: 10"
