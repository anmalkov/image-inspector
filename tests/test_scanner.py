"""Tests for the Trivy scanner: parsing, enumeration and v3 report building (Trivy stubbed)."""

import gzip
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from image_inspector import scanner
from image_inspector.models import ImageTag


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry(d: str, *, t: str | None = None, c: list[int] | None = None) -> dict:
    """Build a compact v3 history entry ``{d, t, c}``."""
    return {"d": d, "t": t, "c": c if c is not None else [0, 0, 0, 0, 0]}


def _tag(*entries: dict) -> dict:
    return {"history": list(entries)}


def _report(tags: dict, **header) -> dict:
    return {"schema_version": 3, "tags": tags, **header}


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


def test_enumerate_targets_carries_created_from_last_updated(monkeypatch):
    from image_inspector.models import Language, RegistryKind

    python = Language("python", "Python", RegistryKind.DOCKER_HUB, "library/python")

    class _DatedProvider(_FakeProvider):
        def resolve(self, tag):
            return ImageTag(
                name=tag,
                digest=self._digests[tag],
                last_updated=datetime(2026, 6, 11, 8, 0, 0, tzinfo=UTC),
            )

    monkeypatch.setattr(scanner, "make_client", _fake_client)
    monkeypatch.setattr(scanner, "get_provider", lambda lang, client: _DatedProvider())

    targets = {t.reference: t for t in scanner.enumerate_targets((python,))}
    assert targets["python:3.13.14"].created == "2026-06-11T08:00:00Z"


def test_build_report_skips_failed_scans(monkeypatch):
    targets = [
        scanner.ScanTarget(
            "python:3.13.14", "python@sha256:ok", "sha256:ok", "2026-06-20T00:00:00Z"
        ),
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
    assert report["schema_version"] == 3
    assert report["trivy_version"] == "0.58.0"
    assert report["trivy_db_updated_at"] == "2026-06-14T12:00:00Z"
    assert set(report["tags"]) == {"python:3.13.14"}
    history = report["tags"]["python:3.13.14"]["history"]
    assert len(history) == 1
    assert history[0]["d"] == "ok"
    assert history[0]["t"] == "2026-06-20T00:00:00Z"
    assert history[0]["c"] == [0, 1, 0, 0, 0]


def test_main_language_filter_selects_subset(monkeypatch):
    from image_inspector.models import LANGUAGES_BY_KEY

    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(scanner, "_update_db", lambda: None)
    monkeypatch.setattr(scanner, "_write_report", lambda *a, **k: None)

    captured = {}

    def _fake_build(languages=scanner.LANGUAGES):
        captured["languages"] = languages
        return _report({})

    monkeypatch.setattr(scanner, "build_report", _fake_build)

    assert scanner.main(["--language", "alpine", "-l", "python", "-l", "alpine"]) == 0
    # Order preserved, duplicates removed.
    assert captured["languages"] == (LANGUAGES_BY_KEY["alpine"], LANGUAGES_BY_KEY["python"])


def test_main_no_filter_scans_all(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(scanner, "_update_db", lambda: None)
    monkeypatch.setattr(scanner, "_write_report", lambda *a, **k: None)

    captured = {}

    def _fake_build(languages=scanner.LANGUAGES):
        captured["languages"] = languages
        return _report({})

    monkeypatch.setattr(scanner, "build_report", _fake_build)

    assert scanner.main([]) == 0
    assert captured["languages"] is scanner.LANGUAGES


def test_merge_reports_unions_tags_by_reference():
    a = _report(
        {"python:3.13.14": _tag(_entry("py", t="2026-06-10T00:00:00Z"))},
        generated_at="2026-06-15T02:00:00Z",
        trivy_version="0.71.1",
        trivy_db_updated_at="2026-06-14T12:00:00Z",
    )
    b = _report(
        {"alpine:3.21.0": _tag(_entry("al", t="2026-06-11T00:00:00Z"))},
        generated_at="2026-06-15T02:05:00Z",
        trivy_version=None,
        trivy_db_updated_at=None,
    )
    merged = scanner.merge_reports([a, b])
    assert set(merged["tags"]) == {"python:3.13.14", "alpine:3.21.0"}
    # trivy_version taken from the first input that has one.
    assert merged["trivy_version"] == "0.71.1"
    # DB date likewise collapses to the first non-null value.
    assert merged["trivy_db_updated_at"] == "2026-06-14T12:00:00Z"
    # generated_at is the latest of the inputs.
    assert merged["generated_at"] == "2026-06-15T02:05:00Z"


def test_merge_reports_dedupes_histories_per_shared_tag():
    a = _report({"python:3.13.14": _tag(_entry("d1", t="2026-06-10T00:00:00Z"))})
    b = _report(
        {
            "python:3.13.14": _tag(
                _entry("d1", t="2026-06-10T00:00:00Z"),
                _entry("d2", t="2026-06-09T00:00:00Z"),
            )
        }
    )
    merged = scanner.merge_reports([a, b])
    digests = {e["d"] for e in merged["tags"]["python:3.13.14"]["history"]}
    assert digests == {"d1", "d2"}


def test_trivy_db_updated_at_reads_payload(monkeypatch):
    payload = {"Version": "0.71.1", "VulnerabilityDB": {"UpdatedAt": "2026-06-14T12:00:00Z"}}
    monkeypatch.setattr(scanner, "_trivy_version_payload", lambda: payload)
    assert scanner.trivy_version() == "0.71.1"
    assert scanner.trivy_db_updated_at() == "2026-06-14T12:00:00Z"


def test_trivy_db_updated_at_missing_db(monkeypatch):
    monkeypatch.setattr(scanner, "_trivy_version_payload", lambda: {"Version": "0.71.1"})
    assert scanner.trivy_db_updated_at() is None


def test_merge_main_writes_combined_report(tmp_path):
    now = datetime.now(UTC)
    a = tmp_path / "report-python.json"
    b = tmp_path / "report-alpine.json"
    a.write_text(
        json.dumps(_report({"python:3.13.14": _tag(_entry("py", t=_iso(now)))})), encoding="utf-8"
    )
    b.write_text(
        json.dumps(_report({"alpine:3.21.0": _tag(_entry("al", t=_iso(now)))})), encoding="utf-8"
    )
    out = tmp_path / "combined.json"

    assert scanner.merge_main([str(a), str(b), "-o", str(out)]) == 0

    combined = json.loads(out.read_text(encoding="utf-8"))
    assert set(combined["tags"]) == {"python:3.13.14", "alpine:3.21.0"}


def test_merge_main_reports_unreadable_input(tmp_path):
    missing = tmp_path / "nope.json"
    out = tmp_path / "combined.json"
    assert scanner.merge_main([str(missing), "-o", str(out)]) == 1
    assert not out.exists()


def test_merge_main_reads_gzip_input(tmp_path):
    now = datetime.now(UTC)
    partial = tmp_path / "report-python.json.gz"
    text = json.dumps(_report({"python:3.13.14": _tag(_entry("py", t=_iso(now)))}))
    partial.write_bytes(gzip.compress(text.encode("utf-8")))
    out = tmp_path / "combined.json"
    assert scanner.merge_main([str(partial), "-o", str(out)]) == 0
    assert set(json.loads(out.read_text(encoding="utf-8"))["tags"]) == {"python:3.13.14"}


# --- Report writing --------------------------------------------------------------------------


def test_write_report_gzips_when_gz_suffix(tmp_path):
    report = _report({"python:3.13.14": _tag(_entry("a", t=None))})
    out = tmp_path / "report.json.gz"
    scanner._write_report(report, out)
    raw = out.read_bytes()
    assert raw[:2] == b"\x1f\x8b"  # gzip magic bytes
    loaded = json.loads(gzip.decompress(raw).decode("utf-8"))
    assert loaded["tags"]["python:3.13.14"]["history"][0]["d"] == "a"


def test_write_report_plain_when_no_gz_suffix(tmp_path):
    report = _report({"python:3.13.14": _tag(_entry("a", t=None))})
    out = tmp_path / "report.json"
    scanner._write_report(report, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == 3


def test_write_report_gzip_is_reproducible(tmp_path):
    report = _report({"python:3.13.14": _tag(_entry("a", t="2026-06-10T00:00:00Z"))})
    out1 = tmp_path / "a.json.gz"
    out2 = tmp_path / "b.json.gz"
    scanner._write_report(report, out1)
    scanner._write_report(report, out2)
    # mtime=0 keeps identical content byte-for-byte identical across writes.
    assert out1.read_bytes() == out2.read_bytes()


# --- Retention -------------------------------------------------------------------------------


def test_apply_retention_caps_per_tag():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    history = [_entry(f"d{i:02d}", t=_iso(now - timedelta(days=i))) for i in range(35)]
    tags = {"python:3.13": {"history": history}}

    kept = scanner.apply_retention(tags, now=now)
    refs = [e["d"] for e in kept["python:3.13"]["history"]]

    # Per-tag cap keeps only the newest-by-created-at entries (i = 0..29).
    assert len(refs) == scanner.RETENTION_MAX_PER_TAG
    assert "d00" in refs and "d29" in refs
    assert "d30" not in refs and "d34" not in refs


def test_apply_retention_ages_out_via_successor_created_at():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    tags = {
        "python:3.12": {
            "history": [
                _entry("live", t=_iso(now - timedelta(days=5))),
                _entry("mid", t=_iso(now - timedelta(days=200))),
                _entry("old", t=_iso(now - timedelta(days=400))),
            ]
        }
    }
    kept = [e["d"] for e in scanner.apply_retention(tags, now=now)["python:3.12"]["history"]]
    # "old" was superseded 200 days ago (> 180), so it ages out; the head never ages out and
    # "mid" was superseded only 5 days ago, so both survive.
    assert kept == ["live", "mid"]


def test_apply_retention_head_never_ages_out():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    tags = {"python:3.10": {"history": [_entry("ancient", t=_iso(now - timedelta(days=900)))]}}
    kept = scanner.apply_retention(tags, now=now)
    assert [e["d"] for e in kept["python:3.10"]["history"]] == ["ancient"]


def test_apply_retention_undated_entry_sorts_last_and_is_retained():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    tags = {
        "python:3.9": {
            "history": [
                _entry("head", t=_iso(now - timedelta(days=1))),
                _entry("undated", t=None),
            ]
        }
    }
    kept = [e["d"] for e in scanner.apply_retention(tags, now=now)["python:3.9"]["history"]]
    # Undated entries never age out, sort last, and still count toward the cap.
    assert kept == ["head", "undated"]


def test_merge_with_history_keeps_old_digest_on_tag_move():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    prior = _report(
        {"python:3.13.15": _tag(_entry("old", t=_iso(now - timedelta(days=3)), c=[0, 1, 0, 0, 0]))}
    )
    fresh = _report(
        {"python:3.13.15": _tag(_entry("new", t=_iso(now), c=[0, 2, 0, 0, 0]))},
        generated_at=_iso(now),
        trivy_version="0.71.1",
        trivy_db_updated_at="2026-06-14T12:00:00Z",
    )
    merged = scanner.merge_with_history(fresh, prior, now=now)
    digests = {e["d"] for e in merged["tags"]["python:3.13.15"]["history"]}
    assert digests == {"old", "new"}
    # Header metadata comes from the fresh run.
    assert merged["trivy_version"] == "0.71.1"
    assert merged["generated_at"] == _iso(now)


def test_merge_with_history_fresh_wins_per_digest():
    now = datetime(2026, 6, 25, tzinfo=UTC)
    prior = _report(
        {"go:1.22": _tag(_entry("x", t=_iso(now - timedelta(days=1)), c=[0, 0, 9, 0, 0]))},
        trivy_version="old",
        generated_at=_iso(now - timedelta(days=1)),
    )
    fresh = _report(
        {"go:1.22": _tag(_entry("x", t=_iso(now), c=[0, 0, 3, 0, 0]))},
        trivy_version="new",
        generated_at=_iso(now),
    )
    merged = scanner.merge_with_history(fresh, prior, now=now)
    history = merged["tags"]["go:1.22"]["history"]
    assert len(history) == 1
    assert history[0]["c"] == [0, 0, 3, 0, 0]
    assert merged["trivy_version"] == "new"


# --- History re-scoring in build_report ------------------------------------------------------


def _python_language():
    from image_inspector.models import Language, RegistryKind

    return Language("python", "Python", RegistryKind.DOCKER_HUB, "library/python")


def test_build_report_rescans_retained_digest(monkeypatch):
    python = _python_language()
    current = [
        scanner.ScanTarget(
            "python:3.13.15", "python@sha256:new", "sha256:new", "2026-06-20T00:00:00Z"
        )
    ]
    monkeypatch.setattr(scanner, "enumerate_targets", lambda *a, **k: iter(current))
    monkeypatch.setattr(scanner, "trivy_version", lambda: "0.71.1")
    monkeypatch.setattr(scanner, "trivy_db_updated_at", lambda: "2026-06-14T12:00:00Z")

    def _fake_scan(image_ref):
        high = 9 if image_ref.endswith("old") else 1
        return {"critical": 0, "high": high, "medium": 0, "low": 0, "unknown": 0, "total": high}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    prior = _report(
        {"python:3.13.15": _tag(_entry("old", t="2026-03-01T00:00:00Z", c=[0, 2, 0, 0, 0]))}
    )
    report = scanner.build_report((python,), prior=prior)

    history = report["tags"]["python:3.13.15"]["history"]
    by_d = {e["d"]: e for e in history}
    assert set(by_d) == {"new", "old"}
    # Re-scored counts, but the created-at (t) is preserved from the prior report.
    assert by_d["old"]["c"] == [0, 9, 0, 0, 0]
    assert by_d["old"]["t"] == "2026-03-01T00:00:00Z"
    # The current digest takes its created-at from the enumerated target.
    assert by_d["new"]["c"] == [0, 1, 0, 0, 0]
    assert by_d["new"]["t"] == "2026-06-20T00:00:00Z"
    # History is ordered newest-created-first, so the live digest is the head.
    assert history[0]["d"] == "new"


def test_build_report_carries_forward_failed_rescan(monkeypatch):
    python = _python_language()
    current = [
        scanner.ScanTarget(
            "python:3.13.15", "python@sha256:new", "sha256:new", "2026-06-20T00:00:00Z"
        )
    ]
    monkeypatch.setattr(scanner, "enumerate_targets", lambda *a, **k: iter(current))
    monkeypatch.setattr(scanner, "trivy_version", lambda: "0.71.1")
    monkeypatch.setattr(scanner, "trivy_db_updated_at", lambda: None)

    def _fake_scan(image_ref):
        if image_ref.endswith("old"):
            return None
        return {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0, "total": 1}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    prior_entry = _entry("old", t="2026-03-01T00:00:00Z", c=[0, 2, 0, 0, 0])
    prior = _report({"python:3.13.15": _tag(dict(prior_entry))})
    report = scanner.build_report((python,), prior=prior)

    by_d = {e["d"]: e for e in report["tags"]["python:3.13.15"]["history"]}
    # A retained digest that can't be re-scored keeps its last-known entry unchanged.
    assert by_d["old"] == prior_entry


def test_build_report_migrates_v2_prior(monkeypatch):
    python = _python_language()
    current = [
        scanner.ScanTarget(
            "python:3.13.15", "python@sha256:new", "sha256:new", "2026-06-20T00:00:00Z"
        )
    ]
    monkeypatch.setattr(scanner, "enumerate_targets", lambda *a, **k: iter(current))
    monkeypatch.setattr(scanner, "trivy_version", lambda: "0.71.1")
    monkeypatch.setattr(scanner, "trivy_db_updated_at", lambda: None)

    def _fake_scan(image_ref):
        high = 5 if image_ref.endswith("old") else 1
        return {"critical": 0, "high": high, "medium": 0, "low": 0, "unknown": 0, "total": high}

    monkeypatch.setattr(scanner, "scan_image", _fake_scan)

    # Legacy v2 prior payload (flat-by-digest); history must survive the cutover.
    prior = {
        "images": {
            "sha256:old": {
                "reference": "python:3.13.15",
                "high": 2,
                "last_active_at": "2026-03-01T00:00:00Z",
            }
        }
    }
    report = scanner.build_report((python,), prior=prior)

    by_d = {e["d"]: e for e in report["tags"]["python:3.13.15"]["history"]}
    assert set(by_d) == {"new", "old"}
    # The migrated digest keeps its created-at (from v2 last_active_at) and is re-scored.
    assert by_d["old"]["t"] == "2026-03-01T00:00:00Z"
    assert by_d["old"]["c"] == [0, 5, 0, 0, 0]


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


def test_generate_sbom_surfaces_stderr_on_failure(monkeypatch, tmp_path, capsys):
    def _run(cmd, **kwargs):
        raise scanner.subprocess.CalledProcessError(1, cmd, stderr="trivy: boom\n")

    monkeypatch.setattr(scanner.subprocess, "run", _run)
    assert scanner.generate_sbom("python@sha256:x", tmp_path / "o.cdx.json") is False
    assert "trivy: boom" in capsys.readouterr().err


def test_score_sbom_surfaces_stderr_on_failure(monkeypatch, tmp_path, capsys):
    def _run(cmd, **kwargs):
        raise scanner.subprocess.CalledProcessError(1, cmd, stderr="sbom: boom\n")

    monkeypatch.setattr(scanner.subprocess, "run", _run)
    assert scanner.score_sbom(tmp_path / "s.cdx.json") is None
    assert "sbom: boom" in capsys.readouterr().err


# --- Prior-report fetch and SBOM publishing --------------------------------------------------


@respx.mock
def test_fetch_prior_report_returns_dict():
    url = "https://example.test/report.json"
    payload = _report({"python:3.13.14": _tag(_entry("a", t=None))})
    respx.get(url).mock(return_value=httpx.Response(200, json=payload))
    assert scanner.fetch_prior_report(url) == payload


@respx.mock
def test_fetch_prior_report_accepts_legacy_v2_images():
    url = "https://example.test/report.json"
    v2 = {"images": {"sha256:a": {"reference": "python:3.13.14", "high": 1}}}
    respx.get(url).mock(return_value=httpx.Response(200, json=v2))
    # A legacy v2 payload is accepted so a cutover keeps prior history.
    assert scanner.fetch_prior_report(url) == v2


@respx.mock
def test_fetch_prior_report_reads_gzip():
    url = "https://example.test/report.json.gz"
    payload = _report({"python:3.13.14": _tag(_entry("a", t=None))})
    body = gzip.compress(json.dumps(payload).encode("utf-8"))
    respx.get(url).mock(return_value=httpx.Response(200, content=body))
    assert scanner.fetch_prior_report(url) == payload


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
            _report(
                {"python:3.13.15": _tag(_entry("new", t=_iso(now), c=[0, 0, 1, 0, 0]))},
                generated_at=_iso(now),
                trivy_version="0.71.1",
            )
        ),
        encoding="utf-8",
    )
    url = "https://example.test/report.json"
    prior_created = _iso(now - timedelta(days=5))
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            json=_report(
                {"python:3.13.15": _tag(_entry("old", t=prior_created, c=[0, 0, 2, 0, 0]))}
            ),
        )
    )
    out = tmp_path / "combined.json"

    assert scanner.merge_main([str(partial), "--prior-url", url, "-o", str(out)]) == 0

    combined = json.loads(out.read_text(encoding="utf-8"))
    digests = {e["d"] for e in combined["tags"]["python:3.13.15"]["history"]}
    assert digests == {"new", "old"}
    assert combined["trivy_version"] == "0.71.1"


def test_merge_main_gzip_output(tmp_path):
    now = datetime.now(UTC)
    partial = tmp_path / "report-python.json"
    partial.write_text(
        json.dumps(
            _report({"python:3.13.14": _tag(_entry("py", t=_iso(now)))}, generated_at=_iso(now))
        ),
        encoding="utf-8",
    )
    out = tmp_path / "combined.json"
    gz = tmp_path / "combined.json.gz"

    assert scanner.merge_main([str(partial), "-o", str(out), "--gzip-output", str(gz)]) == 0

    assert out.exists()
    raw = gz.read_bytes()
    assert raw[:2] == b"\x1f\x8b"
    loaded = json.loads(gzip.decompress(raw).decode("utf-8"))
    assert loaded["tags"]["python:3.13.14"]["history"][0]["d"] == "py"


def test_merge_main_publishes_retained_sboms(tmp_path):
    now = datetime.now(UTC)
    partial = tmp_path / "report-python.json"
    partial.write_text(
        json.dumps(
            _report({"python:3.13.15": _tag(_entry("keep", t=_iso(now)))}, generated_at=_iso(now))
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


@pytest.mark.parametrize("flag", ["--sbom-src-dir", "--sbom-out-dir"])
def test_merge_main_requires_both_sbom_dirs(tmp_path, flag):
    partial = tmp_path / "report-python.json"
    partial.write_text(json.dumps(_report({})), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        scanner.merge_main(
            [str(partial), flag, str(tmp_path / "d"), "-o", str(tmp_path / "o.json")]
        )
    assert exc.value.code == 2


def test_main_passes_prior_and_sbom_store(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/trivy")
    monkeypatch.setattr(scanner, "_update_db", lambda: None)
    monkeypatch.setattr(scanner, "fetch_prior_report", lambda url: {"tags": {}, "_url": url})
    monkeypatch.setattr(scanner, "_write_report", lambda *a, **k: None)

    captured = {}

    def _fake_build(languages=scanner.LANGUAGES, **kwargs):
        captured.update(kwargs)
        captured["languages"] = languages
        return _report({})

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
    assert captured["prior"] == {"tags": {}, "_url": "http://x/report.json"}
    assert isinstance(captured["sbom_store"], scanner.SbomStore)
    assert captured["sbom_store"].base_url == "http://x"
