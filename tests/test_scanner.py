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

    def _fake_scan(image_ref):
        if image_ref.endswith("bad"):
            return None
        return {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0, "total": 1}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    report = scanner.build_report()
    assert report["trivy_version"] == "0.58.0"
    assert set(report["images"]) == {"sha256:ok"}
    assert report["images"]["sha256:ok"]["high"] == 1
    assert report["images"]["sha256:ok"]["reference"] == "python:3.13.14"
