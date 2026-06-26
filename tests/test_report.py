"""Tests for the vulnerability report loader (v3 ``tags``/``history`` payloads)."""

import gzip
import json
import os
from datetime import UTC, datetime
from pathlib import Path

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


def _strip(digest: str) -> str:
    return digest[7:] if digest.startswith("sha256:") else digest


def _payload(digest: str, *, schema_version: int = 3) -> dict:
    """A minimal v3 report whose single history entry resolves to ``digest``."""
    return {
        "schema_version": schema_version,
        "generated_at": "2026-06-15T02:00:00Z",
        "trivy_version": "0.58.0",
        "tags": {
            "python:3.13.14-slim": {
                "history": [
                    {"d": _strip(digest), "t": "2026-06-11T07:00:00Z", "c": [1, 2, 3, 4, 0]},
                ]
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
    "schema_version": 3,
    "generated_at": "2026-06-15T02:00:00Z",
    "trivy_version": "0.58.0",
    "trivy_db_updated_at": "2026-06-14T12:00:00Z",
    "tags": {
        "python:3.13.14-slim": {
            "history": [
                {"d": "abc", "t": "2026-06-11T07:00:00Z", "c": [1, 2, 3, 4, 0]},
            ]
        }
    },
}


def test_from_dict_parses_metadata_and_images():
    report = VulnerabilityReport.from_dict(_SAMPLE)
    assert report.trivy_version == "0.58.0"
    assert report.generated_at == datetime(2026, 6, 15, 2, 0, 0, tzinfo=UTC)
    assert report.trivy_db_updated_at == datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC)
    vulns = report.lookup_digest("sha256:abc")
    # total is derived (sum of c); scanned_at is the report's generated_at in v3.
    assert vulns == ImageVulnerabilities(
        critical=1,
        high=2,
        medium=3,
        low=4,
        unknown=0,
        total=10,
        scanned_at=datetime(2026, 6, 15, 2, 0, 0, tzinfo=UTC),
    )


def test_from_dict_indexes_latest_per_tag():
    sample = {
        "schema_version": 3,
        "generated_at": "2026-06-15T02:00:00Z",
        "tags": {
            "python:3.13.14-slim": {
                "history": [
                    {"d": "head", "t": "2026-06-11T07:00:00Z", "c": [0, 1, 0, 0, 0]},
                    {"d": "older", "t": "2026-06-01T07:00:00Z", "c": [0, 9, 0, 0, 0]},
                ]
            }
        },
    }
    report = VulnerabilityReport.from_dict(sample)
    # latest_for_tag resolves the head (index 0) of the tag's history.
    assert report.latest_for_tag("python:3.13.14-slim").high == 1
    assert report.latest_for_tag("python:does-not-exist") is None
    assert report.latest_for_tag(None) is None
    # both digests are still indexed for digest lookups.
    assert report.lookup_digest("sha256:older").high == 9


def test_from_dict_tolerates_missing_db_date_and_nanoseconds():
    # Older reports lack trivy_db_updated_at; Trivy emits nanosecond timestamps.
    no_db = VulnerabilityReport.from_dict({"trivy_version": "0.71.1"})
    assert no_db.trivy_db_updated_at is None

    nanos = VulnerabilityReport.from_dict({"trivy_db_updated_at": "2026-06-14T12:00:00.123456789Z"})
    assert nanos.trivy_db_updated_at == datetime(2026, 6, 14, 12, 0, 0, 123456, tzinfo=UTC)


def test_lookup_missing_or_none_digest_returns_none():
    report = VulnerabilityReport.from_dict(_SAMPLE)
    assert report.lookup_digest("sha256:does-not-exist") is None
    assert report.lookup_digest(None) is None


def test_empty_report_has_no_images():
    report = VulnerabilityReport.empty()
    assert report.images == {}
    assert report.lookup_digest("sha256:abc") is None
    assert report.source is None


@respx.mock
def test_load_report_online_prefers_fetched(isolate_loader):
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST)))
    report = load_report()
    assert report.source is ReportSource.ONLINE
    assert report.lookup_digest(_ONLINE_DIGEST) is not None
    assert report.lookup_digest(_PACKAGED_DIGEST) is None


@respx.mock
def test_load_report_online_reads_gzip(isolate_loader):
    body = gzip.compress(json.dumps(_payload(_ONLINE_DIGEST)).encode("utf-8"))
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, content=body))
    report = load_report()
    assert report.source is ReportSource.ONLINE
    assert report.lookup_digest(_ONLINE_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_when_offline(isolate_loader):
    respx.get(isolate_loader).mock(side_effect=httpx.ConnectError("offline"))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_on_non_200(isolate_loader):
    respx.get(isolate_loader).mock(return_value=httpx.Response(503))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_on_malformed_payload(isolate_loader):
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, text="not json{"))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_on_older_schema(isolate_loader):
    # An *older* online schema is a normal quiet offline fallback, not an outdated-tool case.
    respx.get(isolate_loader).mock(
        return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST, schema_version=2))
    )
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_outdated_on_newer_schema(isolate_loader):
    # A newer-than-supported online schema means the tool is behind the published data:
    # fall back to the bundled copy but mark it OUTDATED so the UI can warn the user.
    respx.get(isolate_loader).mock(
        return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST, schema_version=4))
    )
    report = load_report()
    assert report.source is ReportSource.OUTDATED
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None
    assert report.lookup_digest(_ONLINE_DIGEST) is None


@respx.mock
def test_load_report_outdated_requires_dict_payload(isolate_loader):
    # A newer schema_version on a non-report body (e.g. a list) is not the outdated signal;
    # it degrades to the quiet offline fallback.
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    report = load_report()
    assert report.source is ReportSource.OFFLINE


@respx.mock
def test_load_report_outdated_empty_when_no_packaged(isolate_loader, monkeypatch):
    # Newer online schema but no packaged copy: degrade to an empty report (never crash).
    respx.get(isolate_loader).mock(
        return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST, schema_version=4))
    )
    monkeypatch.setattr(report_module, "_load_packaged", lambda: None)
    report = load_report()
    assert report.source is None
    assert report.images == {}


@respx.mock
def test_load_report_uses_cached_body_on_304(isolate_loader):
    route = respx.get(isolate_loader)
    # First call: 200 with an ETag populates the on-disk cache.
    route.mock(
        return_value=httpx.Response(200, headers={"ETag": '"v1"'}, json=_payload(_ONLINE_DIGEST))
    )
    first = load_report()
    assert first.source is ReportSource.ONLINE
    assert first.lookup_digest(_ONLINE_DIGEST) is not None

    # Second call: server replies 304, so the cached body is reused.
    route.mock(return_value=httpx.Response(304))
    second = load_report()
    assert second.source is ReportSource.ONLINE
    assert second.lookup_digest(_ONLINE_DIGEST) is not None
    # The conditional request carried the stored ETag.
    assert route.calls.last.request.headers.get("If-None-Match") == '"v1"'


@respx.mock
def test_load_report_outdated_on_304_with_newer_cached_schema(isolate_loader):
    # A newer tool version (or a later downgrade) could have populated the shared cache
    # with a newer-schema body. On a 304 we must re-check the cached body and flag the
    # tool as OUTDATED rather than silently degrading to OFFLINE.
    cache_path = report_module._cache_path()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "url": isolate_loader,
                "etag": '"v4"',
                "body": json.dumps(_payload(_ONLINE_DIGEST, schema_version=4)),
            }
        ),
        encoding="utf-8",
    )
    respx.get(isolate_loader).mock(return_value=httpx.Response(304))
    report = load_report()
    assert report.source is ReportSource.OUTDATED
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None
    assert report.lookup_digest(_ONLINE_DIGEST) is None


@respx.mock
def test_load_report_offline_env_skips_fetch(isolate_loader, monkeypatch):
    monkeypatch.setenv("IMAGE_INSPECTOR_OFFLINE", "1")
    route = respx.get(isolate_loader).mock(
        return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST))
    )
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None
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


@respx.mock
def test_load_report_falls_back_when_tags_not_dict(isolate_loader):
    # schema_version is fine but tags is a list, not a dict: must not crash from_dict.
    bad = {"schema_version": 3, "trivy_version": "0.58.0", "tags": []}
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, json=bad))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None


@respx.mock
def test_load_report_falls_back_when_entry_malformed(isolate_loader):
    # Passes _validate_payload (tags is a dict) but a history entry's counts are non-numeric,
    # which crashes ImageVulnerabilities.from_compact -- must fall back to the packaged copy.
    bad = {
        "schema_version": 3,
        "trivy_version": "0.58.0",
        "tags": {"python:3.13.14-slim": {"history": [{"d": "bad", "c": ["x"]}]}},
    }
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, json=bad))
    report = load_report()
    assert report.source is ReportSource.OFFLINE
    assert report.lookup_digest(_PACKAGED_DIGEST) is not None


def test_load_report_empty_when_packaged_entry_malformed(monkeypatch):
    # The packaged copy itself has a malformed entry: _build_report must swallow the error
    # and degrade to an empty report rather than crashing startup.
    monkeypatch.setenv("IMAGE_INSPECTOR_OFFLINE", "1")
    monkeypatch.setattr(
        report_module,
        "_load_packaged",
        lambda: {
            "schema_version": 3,
            "tags": {"python:3.13.14-slim": {"history": [{"d": "bad", "c": ["x"]}]}},
        },
    )
    report = load_report()
    assert report.source is None
    assert report.images == {}


class _FakeResource:
    """Stand-in for importlib.resources.files(...).joinpath(...) in _load_packaged tests."""

    def __init__(self, *, data: bytes | None = None, exc: Exception | None = None) -> None:
        self._data = data
        self._exc = exc

    def joinpath(self, *_args: str) -> "_FakeResource":
        return self

    def read_bytes(self, *_args: object, **_kwargs: object) -> bytes:
        if self._exc is not None:
            raise self._exc
        assert self._data is not None
        return self._data


def test_load_packaged_accepts_valid(monkeypatch):
    monkeypatch.setattr(
        report_module.resources,
        "files",
        lambda _pkg: _FakeResource(data=json.dumps(_payload(_PACKAGED_DIGEST)).encode("utf-8")),
    )
    data = report_module._load_packaged()
    assert data is not None
    assert "python:3.13.14-slim" in data["tags"]


def test_load_packaged_reads_gzip(monkeypatch):
    body = gzip.compress(json.dumps(_payload(_PACKAGED_DIGEST)).encode("utf-8"))
    monkeypatch.setattr(report_module.resources, "files", lambda _pkg: _FakeResource(data=body))
    data = report_module._load_packaged()
    assert data is not None
    assert "python:3.13.14-slim" in data["tags"]


def test_load_packaged_rejects_invalid_schema(monkeypatch):
    # tags present but not a dict: _validate_payload rejects it -> packaged load miss.
    monkeypatch.setattr(
        report_module.resources,
        "files",
        lambda _pkg: _FakeResource(data=b'{"schema_version": 3, "tags": []}'),
    )
    assert report_module._load_packaged() is None


def test_load_packaged_is_non_fatal_on_invalid_bytes(monkeypatch):
    # Non-UTF-8 bytes that aren't a gzip stream decode to None instead of crashing.
    monkeypatch.setattr(
        report_module.resources,
        "files",
        lambda _pkg: _FakeResource(data=b"\xff\xfe not valid utf-8"),
    )
    assert report_module._load_packaged() is None


def test_load_packaged_is_non_fatal_on_read_error(monkeypatch):
    monkeypatch.setattr(
        report_module.resources,
        "files",
        lambda _pkg: _FakeResource(exc=OSError("boom")),
    )
    assert report_module._load_packaged() is None


@respx.mock
def test_corrupt_cache_is_non_fatal(isolate_loader):
    # A non-UTF-8 / unparsable cache file must be treated as a miss, not crash the loader.
    cache_path = report_module._cache_path()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(b"\xff\xfe not valid utf-8 or json")
    respx.get(isolate_loader).mock(return_value=httpx.Response(200, json=_payload(_ONLINE_DIGEST)))
    report = load_report()
    assert report.source is ReportSource.ONLINE
    assert report.lookup_digest(_ONLINE_DIGEST) is not None


def test_read_cache_coerces_wrong_types(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "cache"))
    url = "https://example.test/report.json"
    path = report_module._cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # etag as a list and body as a dict must both be coerced to None.
    path.write_text(json.dumps({"url": url, "etag": ["x"], "body": {"a": 1}}), encoding="utf-8")
    assert report_module._read_cache(url) == (None, None)


def test_cache_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "cache"))
    url = "https://example.test/report.json"
    assert report_module._read_cache(url) == (None, None)
    body = json.dumps(_payload(_ONLINE_DIGEST))
    report_module._write_cache(url, '"etag"', body)
    assert report_module._read_cache(url) == ('"etag"', body)
    # A different URL must not return another URL's cached body.
    assert report_module._read_cache("https://other.test/report.json") == (None, None)


def test_cache_dir_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "custom"))
    assert report_module._cache_path() == tmp_path / "custom" / report_module._CACHE_FILENAME


def test_default_cache_dir_uses_xdg(monkeypatch):
    monkeypatch.delenv("IMAGE_INSPECTOR_CACHE_DIR", raising=False)
    monkeypatch.setattr(report_module, "_is_windows", lambda: False)
    monkeypatch.setenv("XDG_CACHE_HOME", "/xdg/cache")
    assert report_module._default_cache_dir() == Path("/xdg/cache") / "image-inspector"


def test_default_cache_dir_falls_back_to_dot_cache(monkeypatch):
    monkeypatch.delenv("IMAGE_INSPECTOR_CACHE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(report_module, "_is_windows", lambda: False)
    monkeypatch.setattr(os.path, "expanduser", lambda _: "/home/user")
    assert report_module._default_cache_dir() == Path("/home/user") / ".cache" / "image-inspector"


def test_default_cache_dir_uses_localappdata_on_windows(monkeypatch):
    monkeypatch.delenv("IMAGE_INSPECTOR_CACHE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(report_module, "_is_windows", lambda: True)
    local = r"C:\\Users\\u\\AppData\\Local"
    monkeypatch.setenv("LOCALAPPDATA", local)
    assert report_module._default_cache_dir() == Path(local) / "image-inspector"


@pytest.fixture
def online(monkeypatch):
    """Drop the offline flag so the PyPI helper actually performs its lookup."""
    monkeypatch.delenv("IMAGE_INSPECTOR_OFFLINE", raising=False)


@respx.mock
def test_latest_pypi_version_returns_info_version(online):
    respx.get(report_module._PYPI_URL).mock(
        return_value=httpx.Response(200, json={"info": {"version": "0.2.1"}})
    )
    assert report_module.latest_pypi_version() == "0.2.1"


@respx.mock
def test_latest_pypi_version_none_on_non_200(online):
    respx.get(report_module._PYPI_URL).mock(return_value=httpx.Response(503))
    assert report_module.latest_pypi_version() is None


@respx.mock
def test_latest_pypi_version_none_on_network_error(online):
    respx.get(report_module._PYPI_URL).mock(side_effect=httpx.ConnectError("offline"))
    assert report_module.latest_pypi_version() is None


@respx.mock
def test_latest_pypi_version_none_on_malformed_json(online):
    respx.get(report_module._PYPI_URL).mock(return_value=httpx.Response(200, text="not json{"))
    assert report_module.latest_pypi_version() is None


@respx.mock
def test_latest_pypi_version_none_when_info_missing(online):
    respx.get(report_module._PYPI_URL).mock(return_value=httpx.Response(200, json={"foo": 1}))
    assert report_module.latest_pypi_version() is None


@respx.mock
def test_latest_pypi_version_none_when_version_blank(online):
    respx.get(report_module._PYPI_URL).mock(
        return_value=httpx.Response(200, json={"info": {"version": ""}})
    )
    assert report_module.latest_pypi_version() is None


@respx.mock
def test_latest_pypi_version_skips_when_offline(monkeypatch):
    # The autouse conftest fixture already sets IMAGE_INSPECTOR_OFFLINE=1; the lookup must
    # short-circuit before any network call (the mocked route therefore stays uncalled).
    route = respx.get(report_module._PYPI_URL).mock(
        return_value=httpx.Response(200, json={"info": {"version": "0.2.1"}})
    )
    assert report_module.latest_pypi_version() is None
    assert not route.called
