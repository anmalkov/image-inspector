"""Tests for the lazy critical/high details sidecar: loader + fix-diff helpers."""

import gzip
import json

import httpx
import pytest
import respx

from image_inspector import report as report_module
from image_inspector.report import DetailsReport, Vulnerability, load_details

_DETAILS_URL = "https://example.test/details.json.gz"


def _payload(digests: dict, vulns: list[dict] | None = None, *, schema_version: int = 3) -> dict:
    if vulns is None:
        vulns = [
            {"id": "CVE-2025-1234", "pkg": "openssl", "sev": "C", "fix": "3.3.2"},
            {"id": "CVE-2025-0777", "pkg": "zlib", "sev": "H", "fix": None},
        ]
    return {"schema_version": schema_version, "vulns": vulns, "digests": digests}


@pytest.fixture
def isolate_details(monkeypatch):
    monkeypatch.setenv("IMAGE_INSPECTOR_DETAILS_URL", _DETAILS_URL)
    monkeypatch.delenv("IMAGE_INSPECTOR_OFFLINE", raising=False)
    monkeypatch.setattr(report_module, "_load_packaged_details", lambda: None)
    return _DETAILS_URL


def _gz(payload: dict) -> bytes:
    return gzip.compress(json.dumps(payload).encode("utf-8"), mtime=0)


def test_from_dict_resolves_cve_set():
    report = DetailsReport.from_dict(_payload({"pinned": [0, 1]}))
    cves = report.cve_set("sha256:pinned")
    assert cves == {
        Vulnerability("CVE-2025-1234", "openssl", "C", "3.3.2"),
        Vulnerability("CVE-2025-0777", "zlib", "H", None),
    }


def test_cve_set_unknown_digest_is_empty():
    report = DetailsReport.from_dict(_payload({"pinned": [0]}))
    assert report.cve_set("nope") == frozenset()
    assert report.cve_set(None) == frozenset()


def test_from_dict_skips_out_of_range_indices():
    report = DetailsReport.from_dict(_payload({"d": [0, 5]}))
    assert {v.id for v in report.cve_set("d")} == {"CVE-2025-1234"}


def test_fix_diff_partitions_pinned_against_latest():
    report = DetailsReport.from_dict(_payload({"pinned": [0, 1], "latest": [1]}))
    fixed, still = report.fix_diff("pinned", "latest")
    assert {v.id for v in fixed} == {"CVE-2025-1234"}
    assert {v.id for v in still} == {"CVE-2025-0777"}


def test_load_details_offline_skips_network(monkeypatch):
    monkeypatch.setenv("IMAGE_INSPECTOR_OFFLINE", "1")
    monkeypatch.setattr(report_module, "_load_packaged_details", lambda: _payload({"d": [0]}))
    report = load_details()
    assert report.cve_set("d")


@respx.mock
def test_load_details_prefers_online(isolate_details):
    respx.get(_DETAILS_URL).mock(
        return_value=httpx.Response(200, content=_gz(_payload({"d": [0, 1]})))
    )
    report = load_details()
    assert {v.id for v in report.cve_set("d")} == {"CVE-2025-1234", "CVE-2025-0777"}


@respx.mock
def test_load_details_falls_back_to_packaged(monkeypatch, isolate_details):
    respx.get(_DETAILS_URL).mock(return_value=httpx.Response(503))
    monkeypatch.setattr(report_module, "_load_packaged_details", lambda: _payload({"d": [0]}))
    report = load_details()
    assert {v.id for v in report.cve_set("d")} == {"CVE-2025-1234"}


@respx.mock
def test_load_details_empty_when_nothing_usable(isolate_details):
    respx.get(_DETAILS_URL).mock(return_value=httpx.Response(404))
    report = load_details()
    assert report.digests == {}
    assert report.vulns == ()


@respx.mock
def test_load_details_rejects_wrong_schema(isolate_details):
    respx.get(_DETAILS_URL).mock(
        return_value=httpx.Response(200, content=_gz(_payload({"d": [0]}, schema_version=99)))
    )
    assert load_details().digests == {}
