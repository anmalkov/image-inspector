"""Tests for the vulnerability report loader."""

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from image_inspector import report as report_module
from image_inspector.report import (
    ImageVulnerabilities,
    ReportSource,
    VulnerabilityReport,
    load_report,
)

_PACKAGED_DIGEST = "sha256:packaged"
_ONLINE_DIGEST = "sha256:online"


def _payload(digest: str, *, schema_version: int = 2) -> dict:
    return {
        "schema_version": schema_version,
        "generated_at": "2026-06-15T02:00:00Z",
        "trivy_version": "0.58.0",
        "images": {
            digest: {
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


@pytest.fixture
def isolate_loader(monkeypatch, tmp_path):
    """Force a clean on-disk cache and a known report URL for each test."""
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("IMAGE_INSPECTOR_REPORT_URL", "https://example.test/report.json")
    monkeypatch.delenv("IMAGE_INSPECTOR_OFFLINE", raising=False)
    # Make the packaged fallback deterministic and distinct from the online payload.
    monkeypatch.setattr(report_module, "_load_packaged", lambda: _payload(_PACKAGED_DIGEST))
    return "https://example.test/report.json"


_SAMPLE = {
    "schema_version": 2,
    "generated_at": "2026-06-15T02:00:00Z",
    "trivy_version": "0.58.0",
    "trivy_db_updated_at": "2026-06-14T12:00:00Z",
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
    assert report.trivy_db_updated_at == datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC)
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


def test_from_dict_tolerates_missing_db_date_and_nanoseconds():
    # Older reports lack trivy_db_updated_at; Trivy emits nanosecond timestamps.
    no_db = VulnerabilityReport.from_dict({"trivy_version": "0.71.1"})
    assert no_db.trivy_db_updated_at is None

    nanos = VulnerabilityReport.from_dict({"trivy_db_updated_at": "2026-06-14T12:00:00.123456789Z"})
    assert nanos.trivy_db_updated_at == datetime(2026, 6, 14, 12, 0, 0, 123456, tzinfo=UTC)


def test_lookup_missing_or_none_digest_returns_none():
    report = VulnerabilityReport.from_dict(_SAMPLE)
    assert report.lookup("sha256:does-not-exist") is None
    assert report.lookup(None) is None


def test_empty_report_has_no_images():
    report = VulnerabilityReport.empty()
    assert report.images == {}
    assert report.lookup("sha256:abc") is None
    assert report.source is None


def test_load_report_returns_report_object(monkeypatch):
    # Force the offline path so the test never touches the network; the packaged
    # report.json ships with the wheel.
    monkeypatch.setenv("IMAGE_INSPECTOR_OFFLINE", "1")
    report = load_report()
    assert isinstance(report, VulnerabilityReport)
    assert isinstance(report.images, dict)
    assert report.source is ReportSource.OFFLINE


@respx.mock
def test_load_report_online_prefers_fetched(isolate_loader):
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST)))
    report = load_report()
    assert report.source is ReportSource.ONLINE
    assert report.lookup(_ONLINE_DIGEST) is not None
    assert report.lookup(_PACKAGED_DIGEST) is None


@respx.mock
def test_load_report_falls_back_when_offline(isolate_loader):
    respx.get(isolate_loader).mock(side_effect=httpx.ConnectError("offline"))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_on_non_200(isolate_loader):
    respx.get(isolate_loader).mock(return_value=httpx.Response(503))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_on_malformed_payload(isolate_loader):
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, text="not json{"))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_on_schema_mismatch(isolate_loader):
    respx.get(isolate_loader).mock(
        return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST, schema_version=99))
    )
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_uses_cached_body_on_304(isolate_loader):
    route = respx.get(isolate_loader)
    # First call: 200 with an ETag populates the on-disk cache.
    route.mock(
        return_value=httpx.Response(200, headers={"ETag": '"v1"'}, json=_payload(_ONLINE_DIGEST))
    )
    first = load_report()
    assert first.source is ReportSource.ONLINE
    assert first.lookup(_ONLINE_DIGEST) is not None

    # Second call: server replies 304, so the cached body is reused.
    route.mock(return_value=httpx.Response(304))
    second = load_report()
    assert second.source is ReportSource.ONLINE
    assert second.lookup(_ONLINE_DIGEST) is not None
    # The conditional request carried the stored ETag.
    assert route.calls.last.request.headers.get("If-None-Match") == '"v1"'


@respx.mock
def test_load_report_offline_env_skips_fetch(isolate_loader, monkeypatch):
    monkeypatch.setenv("IMAGE_INSPECTOR_OFFLINE", "1")
    route = respx.get(isolate_loader).mock(
        return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST))
    )
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup(_PACKAGED_DIGEST) is not None
    assert not route.called


@respx.mock
def test_load_report_honours_url_override(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("IMAGE_INSPECTOR_OFFLINE", raising=False)
    custom = "https://custom.test/some/report.json"
    monkeypatch.setenv("IMAGE_INSPECTOR_REPORT_URL", custom)
    route = respx.get(custom).mock(return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST)))
    report = load_report()
    assert route.called
    assert report.source is ReportSource.ONLINE


@respx.mock
def test_load_report_empty_when_all_sources_fail(isolate_loader, monkeypatch):
    respx.get(isolate_loader).mock(side_effect=httpx.ConnectError("offline"))
    monkeypatch.setattr(report_module, "_load_packaged", lambda: None)
    report = load_report()
    assert report.source is None
    assert report.images == {}


def test_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "cache"))
    url = "https://example.test/report.json"
    assert report_module._read_cache(url) == (None, None)
    body = json.dumps(_payload(_ONLINE_DIGEST))
    report_module._write_cache(url, '"etag"', body)
    assert report_module._read_cache(url) == ('"etag"', body)
    # A different URL must not return another URL's cached body.
    assert report_module._read_cache("https://other.test/report.json") == (None, None)
