"""Unit tests for UI helpers."""

from datetime import UTC, datetime

from image_inspector.models import LANGUAGES_BY_KEY, ResolvedImage
from image_inspector.report import ImageVulnerabilities
from image_inspector.ui import (
    copy_to_clipboard,
    format_datetime,
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
    expected = "Critical: 1  ·  High: 2  ·  Total: 10  ·  Scanned: Jun 15, 2026 · 00:00 UTC"
    assert text.plain == expected


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
    )
    payload = result_payload(image)
    assert payload["language"] == "python"
    assert payload["version"] == "3.13.14"
    assert payload["variant"] == "slim"
    assert payload["pinned_reference"] == "python:3.13.14-slim@sha256:deadbeef"
    assert payload["from_line"] == "FROM python:3.13.14-slim@sha256:deadbeef"
    assert payload["vulnerabilities"]["high"] == 2


def test_copy_to_clipboard_emits_osc52(capsys):
    copy_to_clipboard("FROM ubuntu:24.04")
    out = capsys.readouterr().out
    # base64 of "FROM ubuntu:24.04"
    assert out == "\033]52;c;RlJPTSB1YnVudHU6MjQuMDQ=\a"

