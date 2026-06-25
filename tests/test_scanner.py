"""Tests for the Trivy scanner: parsing and enumeration (Trivy is stubbed)."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import respx

from image_inspector import scanner
from image_inspector.models import ImageTag


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry(reference, *, total=0, high=0, scanned_at=None, last_active_at=None):
    entry = {"reference": reference, "total": total, "high": high}
    if scanned_at is not None:
        entry["scanned_at"] = scanned_at
    if last_active_at is not None:
        entry["last_active_at"] = last_active_at
    return entry


class _FakeProc:
    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.stderr = ""


def _no_generate(*_args, **_kwargs):
    raise AssertionError("generate_sbom should not be called")


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

    combined = json.loads(out.read_text(encoding="utf-8"))
    assert set(combined["images"]) == {"sha256:py", "sha256:al"}


def test_merge_main_reports_unreadable_input(tmp_path):
    missing = tmp_path / "nope.json"
    out = tmp_path / "combined.json"
    assert scanner.merge_main([str(missing), "-o", str(out)]) == 1
    assert not out.exists()


# --- Retention -------------------------------------------------------------------------------


def test_apply_retention_drops_old_and_caps_per_tag():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    images = {
        f"sha256:d{i:02d}": _entry(
            "python:3.13", total=i, last_active_at=_iso(now - timedelta(days=i))
        )
        for i in range(35)
    }
    images["sha256:stale"] = _entry("python:3.12", last_active_at=_iso(now - timedelta(days=200)))
    images["sha256:fresh"] = _entry("python:3.12", last_active_at=_iso(now - timedelta(days=10)))

    kept = scanner.apply_retention(images, now=now)

    py313 = [d for d, e in kept.items() if e["reference"] == "python:3.13"]
    # Per-tag cap keeps only the 30 most-recently-active digests (i = 0..29).
    assert len(py313) == scanner.RETENTION_MAX_PER_TAG
    assert "sha256:d00" in kept and "sha256:d29" in kept
    assert "sha256:d30" not in kept and "sha256:d34" not in kept
    # Age window drops the 200-day-old digest but keeps the 10-day-old one.
    assert "sha256:stale" not in kept
    assert "sha256:fresh" in kept


def test_apply_retention_uses_scanned_at_when_last_active_missing():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    images = {
        "sha256:old": _entry("python:3.13", scanned_at=_iso(now - timedelta(days=200))),
        "sha256:new": _entry("python:3.13", scanned_at=_iso(now - timedelta(days=5))),
    }
    kept = scanner.apply_retention(images, now=now)
    assert "sha256:old" not in kept
    assert "sha256:new" in kept


def test_merge_with_history_keeps_old_digest_on_tag_move():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    moved = _iso(now - timedelta(days=3))
    prior = {"images": {"sha256:old": _entry("python:3.13.15", total=1, last_active_at=moved)}}
    fresh = {
        "generated_at": _iso(now),
        "trivy_version": "0.71.1",
        "trivy_db_updated_at": "2026-06-14T12:00:00Z",
        "images": {"sha256:new": _entry("python:3.13.15", total=2, last_active_at=_iso(now))},
    }
    merged = scanner.merge_with_history(fresh, prior, now=now)
    assert set(merged["images"]) == {"sha256:old", "sha256:new"}
    # Header metadata comes from the fresh run.
    assert merged["trivy_version"] == "0.71.1"
    assert merged["generated_at"] == _iso(now)


def test_merge_with_history_fresh_wins_per_digest():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    prior = {
        "images": {
            "sha256:x": _entry("go:1.22", total=9, last_active_at=_iso(now - timedelta(days=1)))
        },
        "trivy_version": "old",
        "generated_at": _iso(now - timedelta(days=1)),
    }
    fresh = {
        "images": {"sha256:x": _entry("go:1.22", total=3, last_active_at=_iso(now))},
        "trivy_version": "new",
        "generated_at": _iso(now),
    }
    merged = scanner.merge_with_history(fresh, prior, now=now)
    assert merged["images"]["sha256:x"]["total"] == 3
    assert merged["trivy_version"] == "new"


# --- History re-scoring in build_report ------------------------------------------------------


def _python_language():
    from image_inspector.models import Language, RegistryKind

    return Language("python", "Python", RegistryKind.DOCKER_HUB, "library/python")


def test_build_report_rescans_retained_digest(monkeypatch):
    python = _python_language()
    current = [scanner.ScanTarget("python:3.13.15", "python@sha256:new", "sha256:new")]
    monkeypatch.setattr(scanner, "enumerate_targets", lambda *a, **k: iter(current))
    monkeypatch.setattr(scanner, "trivy_version", lambda: "0.71.1")
    monkeypatch.setattr(scanner, "trivy_db_updated_at", lambda: "2026-06-14T12:00:00Z")

    def _fake_scan(image_ref):
        high = 9 if image_ref.endswith("old") else 1
        return {"critical": 0, "high": high, "medium": 0, "low": 0, "unknown": 0, "total": high}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    prior = {
        "images": {
            "sha256:old": _entry(
                "python:3.13.15",
                total=2,
                high=2,
                scanned_at="2026-01-01T00:00:00Z",
                last_active_at="2026-03-01T00:00:00Z",
            )
        }
    }
    report = scanner.build_report((python,), prior=prior)

    assert set(report["images"]) == {"sha256:new", "sha256:old"}
    old = report["images"]["sha256:old"]
    # Re-scored counts, refreshed scanned_at, but last_active_at preserved from the prior report.
    assert old["high"] == 9
    assert old["last_active_at"] == "2026-03-01T00:00:00Z"
    assert old["scanned_at"] != "2026-01-01T00:00:00Z"
    new = report["images"]["sha256:new"]
    assert new["last_active_at"] == new["scanned_at"]


def test_build_report_carries_forward_failed_rescan(monkeypatch):
    python = _python_language()
    current = [scanner.ScanTarget("python:3.13.15", "python@sha256:new", "sha256:new")]
    monkeypatch.setattr(scanner, "enumerate_targets", lambda *a, **k: iter(current))
    monkeypatch.setattr(scanner, "trivy_version", lambda: "0.71.1")
    monkeypatch.setattr(scanner, "trivy_db_updated_at", lambda: None)

    def _fake_scan(image_ref):
        if image_ref.endswith("old"):
            return None
        return {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0, "total": 1}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    prior_entry = _entry(
        "python:3.13.15",
        total=2,
        high=2,
        scanned_at="2026-01-01T00:00:00Z",
        last_active_at="2026-03-01T00:00:00Z",
    )
    prior = {"images": {"sha256:old": dict(prior_entry)}}
    report = scanner.build_report((python,), prior=prior)
    # A retained digest that can't be re-scored keeps its last-known counts unchanged.
    assert report["images"]["sha256:old"] == prior_entry


# --- SBOM store and scoring ------------------------------------------------------------------


def test_sbom_store_ensure_cache_hit(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    cache.mkdir()
    out = tmp_path / "out"
    name = scanner._sbom_name("sha256:abc")
    (cache / name).write_text("SBOM", encoding="utf-8")
    monkeypatch.setattr(scanner, "generate_sbom", _no_generate)

    store = scanner.SbomStore(cache, out)
    path = store.ensure("sha256:abc", "python@sha256:abc")

    assert path == cache / name
    assert (out / name).read_text(encoding="utf-8") == "SBOM"


@respx.mock
def test_sbom_store_ensure_fetches_from_pages(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    out = tmp_path / "out"
    name = scanner._sbom_name("sha256:def")
    base = "https://example.test/site"
    respx.get(f"{base}/sbom/{name}").mock(return_value=httpx.Response(200, content=b"FETCHED"))
    monkeypatch.setattr(scanner, "generate_sbom", _no_generate)

    store = scanner.SbomStore(cache, out, base_url=base)
    store.ensure("sha256:def", "python@sha256:def")

    assert (cache / name).read_bytes() == b"FETCHED"
    assert (out / name).read_bytes() == b"FETCHED"


def test_sbom_store_ensure_generates_on_miss(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    out = tmp_path / "out"
    name = scanner._sbom_name("sha256:ghi")

    def _fake_generate(image_ref, out_path):
        Path(out_path).write_text("GEN", encoding="utf-8")
        return True

    monkeypatch.setattr(scanner, "generate_sbom", _fake_generate)

    store = scanner.SbomStore(cache, out)
    path = store.ensure("sha256:ghi", "python@sha256:ghi")

    assert path == cache / name
    assert (out / name).read_text(encoding="utf-8") == "GEN"


def test_sbom_store_ensure_none_when_unavailable(tmp_path, monkeypatch):
    store = scanner.SbomStore(tmp_path / "cache", tmp_path / "out")
    monkeypatch.setattr(scanner, "generate_sbom", lambda *a, **k: False)
    assert store.ensure("sha256:gone", "python@sha256:gone") is None


def test_score_sbom_parses_counts(monkeypatch, tmp_path):
    payload = {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}, {"Severity": "LOW"}]}]}
    captured = {}

    def _run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc(stdout=json.dumps(payload))

    monkeypatch.setattr(scanner.subprocess, "run", _run)
    counts = scanner.score_sbom(tmp_path / "s.cdx.json")

    assert counts["high"] == 1 and counts["low"] == 1 and counts["total"] == 2
    assert captured["cmd"][:2] == ["trivy", "sbom"]


def test_generate_sbom_invokes_trivy(monkeypatch, tmp_path):
    captured = {}

    def _run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(scanner.subprocess, "run", _run)
    out_path = tmp_path / "o.cdx.json"
    assert scanner.generate_sbom("python@sha256:x", out_path) is True
    assert captured["cmd"][:2] == ["trivy", "image"]
    assert "cyclonedx" in captured["cmd"]
    assert str(out_path) in captured["cmd"]


# --- Prior-report fetch and SBOM publishing --------------------------------------------------


@respx.mock
def test_fetch_prior_report_returns_dict():
    url = "https://example.test/report.json"
    respx.get(url).mock(return_value=httpx.Response(200, json={"images": {"sha256:a": {}}}))
    assert scanner.fetch_prior_report(url) == {"images": {"sha256:a": {}}}


@respx.mock
def test_fetch_prior_report_none_on_404():
    url = "https://example.test/report.json"
    respx.get(url).mock(return_value=httpx.Response(404))
    assert scanner.fetch_prior_report(url) is None


@respx.mock
def test_fetch_prior_report_none_on_error():
    url = "https://example.test/report.json"
    respx.get(url).mock(side_effect=httpx.ConnectError("offline"))
    assert scanner.fetch_prior_report(url) is None


def test_publish_sboms_copies_only_retained(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"
    name_a = scanner._sbom_name("sha256:a")
    name_b = scanner._sbom_name("sha256:b")
    (src / name_a).write_text("A", encoding="utf-8")
    (src / name_b).write_text("B", encoding="utf-8")

    copied = scanner.publish_sboms(["sha256:a", "sha256:missing"], src, out)

    assert copied == 1
    assert (out / name_a).exists()
    assert not (out / name_b).exists()


@respx.mock
def test_merge_main_with_prior_url_merges_history(tmp_path):
    now = datetime.now(UTC)
    partial = tmp_path / "report-python.json"
    partial.write_text(
        json.dumps(
            {
                "generated_at": _iso(now),
                "trivy_version": "0.71.1",
                "images": {
                    "sha256:new": _entry("python:3.13.15", total=1, last_active_at=_iso(now))
                },
            }
        ),
        encoding="utf-8",
    )
    url = "https://example.test/report.json"
    prior_active = _iso(now - timedelta(days=5))
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            json={
                "images": {
                    "sha256:old": _entry("python:3.13.15", total=2, last_active_at=prior_active)
                }
            },
        )
    )
    out = tmp_path / "combined.json"

    assert scanner.merge_main([str(partial), "--prior-url", url, "-o", str(out)]) == 0

    combined = json.loads(out.read_text(encoding="utf-8"))
    assert set(combined["images"]) == {"sha256:new", "sha256:old"}
    assert combined["trivy_version"] == "0.71.1"


def test_merge_main_publishes_retained_sboms(tmp_path):
    now = datetime.now(UTC)
    partial = tmp_path / "report-python.json"
    partial.write_text(
        json.dumps(
            {
                "generated_at": _iso(now),
                "images": {"sha256:keep": _entry("python:3.13.15", last_active_at=_iso(now))},
            }
        ),
        encoding="utf-8",
    )
    src = tmp_path / "sboms"
    src.mkdir()
    (src / scanner._sbom_name("sha256:keep")).write_text("KEEP", encoding="utf-8")
    (src / scanner._sbom_name("sha256:drop")).write_text("DROP", encoding="utf-8")
    out_sboms = tmp_path / "pages" / "sbom"
    out = tmp_path / "combined.json"

    rc = scanner.merge_main(
        [str(partial), "--sbom-src-dir", str(src), "--sbom-out-dir", str(out_sboms), "-o", str(out)]
    )

    assert rc == 0
    assert (out_sboms / scanner._sbom_name("sha256:keep")).exists()
    assert not (out_sboms / scanner._sbom_name("sha256:drop")).exists()


def test_main_passes_prior_and_sbom_store(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(scanner, "_update_db", lambda: None)
    monkeypatch.setattr(scanner, "fetch_prior_report", lambda url: {"images": {}, "_url": url})
    monkeypatch.setattr(scanner.json, "dumps", lambda *a, **k: "{}")
    monkeypatch.setattr("pathlib.Path.write_text", lambda self, *a, **k: None)

    captured = {}

    def _fake_build(languages=scanner.LANGUAGES, **kwargs):
        captured.update(kwargs)
        captured["languages"] = languages
        return {"images": {}}

    monkeypatch.setattr(scanner, "build_report", _fake_build)

    rc = scanner.main(
        [
            "-l",
            "python",
            "--prior-url",
            "http://x/report.json",
            "--sbom-out-dir",
            str(tmp_path / "sboms"),
            "--sbom-base-url",
            "http://x",
        ]
    )

    assert rc == 0
    assert captured["prior"] == {"images": {}, "_url": "http://x/report.json"}
    assert isinstance(captured["sbom_store"], scanner.SbomStore)
    assert captured["sbom_store"].base_url == "http://x"
