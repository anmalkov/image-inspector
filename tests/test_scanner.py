"""Tests for the Trivy scanner: parsing and enumeration (Trivy is stubbed)."""

from contextlib import contextmanager

from image_inspector import scanner
from image_inspector.models import ImageTag


def test_parse_trivy_counts_tallies_by_severity():
    payload = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "CRITICAL"},
                    {"Severity": "HIGH"},
                    {"Severity": "HIGH"},
                    {"Severity": "MEDIUM"},
                    {"Severity": "WEIRD"},
                ]
            },
            {"Vulnerabilities": None},
            {},
        ]
    }
    counts = scanner.parse_trivy_counts(payload)
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 0
    # Unknown severities fall back to the "unknown" bucket.
    assert counts["unknown"] == 1
    assert counts["total"] == 5


def test_parse_trivy_counts_empty_payload():
    counts = scanner.parse_trivy_counts({})
    assert counts["total"] == 0


class _FakeProvider:
    def __init__(self):
        self._digests = {"3.13.14": "sha256:plain", "3.13.14-slim": "sha256:slim"}

    def list_tag_names(self, *, want_minors):
        return ["3.13.14", "3.13.14-slim"]

    def resolve(self, tag):
        return ImageTag(name=tag, digest=self._digests[tag], last_updated=None)


@contextmanager
def _fake_client():
    yield object()


def test_enumerate_targets_uses_resolved_digests(monkeypatch):
    from image_inspector.models import Language, RegistryKind

    python = Language("python", "Python", RegistryKind.DOCKER_HUB, "library/python")
    monkeypatch.setattr(scanner, "make_client", _fake_client)
    monkeypatch.setattr(scanner, "get_provider", lambda lang, client: _FakeProvider())

    targets = list(scanner.enumerate_targets((python,)))
    by_ref = {t.reference: t for t in targets}

    assert by_ref["python:3.13.14"].image_ref == "python@sha256:plain"
    assert by_ref["python:3.13.14-slim"].image_ref == "python@sha256:slim"


def test_build_report_skips_failed_scans(monkeypatch):
    targets = [
        scanner.ScanTarget("python:3.13.14", "python@sha256:ok", "sha256:ok"),
        scanner.ScanTarget("python:3.13.14-slim", "python@sha256:bad", "sha256:bad"),
    ]
    monkeypatch.setattr(scanner, "enumerate_targets", lambda *a, **k: iter(targets))
    monkeypatch.setattr(scanner, "trivy_version", lambda: "0.58.0")
    monkeypatch.setattr(scanner, "trivy_db_updated_at", lambda: "2026-06-14T12:00:00Z")

    def _fake_scan(image_ref):
        if image_ref.endswith("bad"):
            return None
        return {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0, "total": 1}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    report = scanner.build_report()
    assert report["trivy_version"] == "0.58.0"
    assert report["trivy_db_updated_at"] == "2026-06-14T12:00:00Z"
    assert set(report["images"]) == {"sha256:ok"}
    assert report["images"]["sha256:ok"]["high"] == 1
    assert report["images"]["sha256:ok"]["reference"] == "python:3.13.14"


def test_main_language_filter_selects_subset(monkeypatch):
    from image_inspector.models import LANGUAGES_BY_KEY

    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(scanner, "_update_db", lambda: None)
    monkeypatch.setattr(scanner.json, "dumps", lambda *a, **k: "{}")
    monkeypatch.setattr("pathlib.Path.write_text", lambda self, *a, **k: None)

    captured = {}

    def _fake_build(languages=scanner.LANGUAGES):
        captured["languages"] = languages
        return {"images": {}}

    monkeypatch.setattr(scanner, "build_report", _fake_build)

    assert scanner.main(["--language", "alpine", "-l", "python", "-l", "alpine"]) == 0
    # Order preserved, duplicates removed.
    assert captured["languages"] == (LANGUAGES_BY_KEY["alpine"], LANGUAGES_BY_KEY["python"])


def test_main_no_filter_scans_all(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(scanner, "_update_db", lambda: None)
    monkeypatch.setattr(scanner.json, "dumps", lambda *a, **k: "{}")
    monkeypatch.setattr("pathlib.Path.write_text", lambda self, *a, **k: None)

    captured = {}

    def _fake_build(languages=scanner.LANGUAGES):
        captured["languages"] = languages
        return {"images": {}}

    monkeypatch.setattr(scanner, "build_report", _fake_build)

    assert scanner.main([]) == 0
    assert captured["languages"] is scanner.LANGUAGES


def test_merge_reports_unions_images_by_digest():
    a = {
        "generated_at": "2026-06-15T02:00:00Z",
        "trivy_version": "0.71.1",
        "trivy_db_updated_at": "2026-06-14T12:00:00Z",
        "images": {"sha256:py": {"reference": "python:3.13.14", "total": 1}},
    }
    b = {
        "generated_at": "2026-06-15T02:05:00Z",
        "trivy_version": None,
        "trivy_db_updated_at": None,
        "images": {"sha256:al": {"reference": "alpine:3.21.0", "total": 0}},
    }
    merged = scanner.merge_reports([a, b])
    assert set(merged["images"]) == {"sha256:py", "sha256:al"}
    # trivy_version taken from the first input that has one.
    assert merged["trivy_version"] == "0.71.1"
    # DB date likewise collapses to the first non-null value.
    assert merged["trivy_db_updated_at"] == "2026-06-14T12:00:00Z"
    # generated_at is the latest of the inputs.
    assert merged["generated_at"] == "2026-06-15T02:05:00Z"


def test_trivy_db_updated_at_reads_payload(monkeypatch):
    payload = {"Version": "0.71.1", "VulnerabilityDB": {"UpdatedAt": "2026-06-14T12:00:00Z"}}
    monkeypatch.setattr(scanner, "_trivy_version_payload", lambda: payload)
    assert scanner.trivy_version() == "0.71.1"
    assert scanner.trivy_db_updated_at() == "2026-06-14T12:00:00Z"


def test_trivy_db_updated_at_missing_db(monkeypatch):
    monkeypatch.setattr(scanner, "_trivy_version_payload", lambda: {"Version": "0.71.1"})
    assert scanner.trivy_db_updated_at() is None


def test_merge_main_writes_combined_report(tmp_path):
    a = tmp_path / "report-python.json"
    b = tmp_path / "report-alpine.json"
    a.write_text('{"images": {"sha256:py": {"reference": "python:3.13.14"}}}', encoding="utf-8")
    b.write_text('{"images": {"sha256:al": {"reference": "alpine:3.21.0"}}}', encoding="utf-8")
    out = tmp_path / "combined.json"

    assert scanner.merge_main([str(a), str(b), "-o", str(out)]) == 0

    import json

    combined = json.loads(out.read_text(encoding="utf-8"))
    assert set(combined["images"]) == {"sha256:py", "sha256:al"}


def test_merge_main_reports_unreadable_input(tmp_path):
    missing = tmp_path / "nope.json"
    out = tmp_path / "combined.json"
    assert scanner.merge_main([str(missing), "-o", str(out)]) == 1
    assert not out.exists()
