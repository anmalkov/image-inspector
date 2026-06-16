"""Unit tests for UI helpers."""

from datetime import UTC, datetime

from image_inspector.models import LANGUAGES_BY_KEY, ResolvedImage, ScanSource
from image_inspector.report import ImageVulnerabilities
from image_inspector.ui import (
    copy_to_clipboard,
    format_datetime,
    format_scan_source,
    format_size,
    format_vulnerabilities,
    result_payload,
)


def test_format_size_units():
    assert format_size(None) == "unknown"
    assert format_size(0) == "0 B"
    assert format_size(512) == "512 B"
    assert format_size(1024) == "1.0 KB"
    assert format_size(20393993) == "19.4 MB"
    assert format_size(3 * 1024**3) == "3.0 GB"


def test_format_datetime_human_readable():
    assert format_datetime(None) == "unknown"
    dt = datetime(2024, 9, 10, 13, 50, tzinfo=UTC)
    assert format_datetime(dt) == "Sep 10, 2024 · 13:50 UTC"


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
    # Counts only; the scanned timestamp is now a separate SECURITY row.
    assert text.plain == "Critical: 1  ·  High: 2  ·  Total: 10"


def test_format_scan_source_full():
    source = ScanSource(version="0.71.1", db_updated_at=datetime(2026, 6, 14, tzinfo=UTC))
    assert format_scan_source(source) == "Trivy v0.71.1 · DB Jun 14, 2026"


def test_format_scan_source_without_db_date():
    assert format_scan_source(ScanSource(version="0.71.1")) == "Trivy v0.71.1"


def test_format_scan_source_none():
    assert format_scan_source(None) is None
    assert format_scan_source(ScanSource(version=None)) is None


def _resolved(**kwargs) -> ResolvedImage:
    base = dict(
        language=LANGUAGES_BY_KEY["ubuntu"],
        tag="24.04",
        digest="sha256:deadbeef",
        created=datetime(2024, 9, 10, 13, 50, tzinfo=UTC),
        size=12345,
        version="24.04",
        variant=None,
    )
    base.update(kwargs)
    return ResolvedImage(**base)


def test_source_label_with_lts():
    image = _resolved(is_lts=True)
    assert image.source_label == "Ubuntu · 24.04 · LTS"


def test_source_label_without_lts():
    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    assert image.source_label == "Python · 3.13.14"


def test_source_label_with_variant():
    image = _resolved(
        language=LANGUAGES_BY_KEY["python"],
        tag="3.13.14-alpine",
        version="3.13.14",
        variant="alpine",
    )
    assert image.source_label == "Python · 3.13.14 · alpine"


def test_result_payload_shape():
    image = _resolved(
        language=LANGUAGES_BY_KEY["python"],
        tag="3.13.14-slim",
        version="3.13.14",
        variant="slim",
        vulnerabilities=ImageVulnerabilities(critical=1, high=2, total=7),
        scan_source=ScanSource(
            version="0.71.1", db_updated_at=datetime(2026, 6, 14, tzinfo=UTC)
        ),
    )
    payload = result_payload(image)
    assert payload["language"] == "python"
    assert payload["version"] == "3.13.14"
    assert payload["variant"] == "slim"
    assert payload["pinned_reference"] == "python:3.13.14-slim@sha256:deadbeef"
    assert payload["from_line"] == "FROM python:3.13.14-slim@sha256:deadbeef"
    assert payload["vulnerabilities"]["high"] == 2
    assert payload["scanner"] == {
        "name": "trivy",
        "version": "0.71.1",
        "db_updated_at": "2026-06-14T00:00:00+00:00",
    }


def test_result_payload_scanner_null_when_unscanned():
    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    payload = result_payload(image)
    assert payload["scanner"] == {"name": "trivy", "version": None, "db_updated_at": None}


def test_result_sections_structure():
    from image_inspector.ui import _result_sections

    image = _resolved(
        language=LANGUAGES_BY_KEY["python"],
        tag="3.13.14-alpine",
        version="3.13.14",
        variant="alpine",
        vulnerabilities=ImageVulnerabilities(
            critical=1, high=2, total=7, scanned_at=datetime(2026, 6, 15, tzinfo=UTC)
        ),
        scan_source=ScanSource(
            version="0.71.1", db_updated_at=datetime(2026, 6, 14, tzinfo=UTC)
        ),
    )
    sections = _result_sections(image)
    titles = [title for title, _ in sections]
    assert titles == ["SELECTED", "IMAGE", "SECURITY"]

    security = next(rows for title, rows in sections if title == "SECURITY")
    labels = {label: value for label, value in security}
    assert set(labels) == {"Vulnerabilities", "Scanned", "Source"}
    assert labels["Source"] == "Trivy v0.71.1 · DB Jun 14, 2026"


def test_result_sections_security_omits_unknown_rows():
    from image_inspector.ui import _result_sections

    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    security = next(rows for title, rows in _result_sections(image) if title == "SECURITY")
    # No scan data: only the Vulnerabilities row, no Scanned/Source.
    assert [label for label, _ in security] == ["Vulnerabilities"]


def test_copy_to_clipboard_emits_osc52(capsys):
    copy_to_clipboard("FROM ubuntu:24.04")
    out = capsys.readouterr().out
    # base64 of "FROM ubuntu:24.04"
    assert out == "\033]52;c;RlJPTSB1YnVudHU6MjQuMDQ=\a"

