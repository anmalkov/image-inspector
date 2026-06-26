"""Tests for the dev-only database stats view (v3 ``tags``/``history`` payloads)."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import respx

from image_inspector import report as report_module
from image_inspector import stats as stats_module
from image_inspector.stats import compute_stats, load_payload, main, stats_payload

# A fixed "now" so the aging-out window is deterministic.
NOW = datetime(2026, 6, 25, 2, 0, 0, tzinfo=UTC)


def _at(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry(digest: str, *, t: str | None, total: int = 0) -> dict:
    # ``c`` is [crit, high, medium, low, unknown]; stash ``total`` under "medium" so callers
    # that only care about a non-zero total stay readable.
    return {"d": digest, "t": t, "c": [0, 0, total, 0, 0]}


def _tag(*entries: dict) -> dict:
    return {"history": list(entries)}


def _payload() -> dict:
    return {
        "schema_version": 3,
        "generated_at": "2026-06-25T02:14:03Z",
        "trivy_version": "0.58.0",
        "trivy_db_updated_at": "2026-06-25T01:30:00Z",
        "tags": {
            # python:3.13.14-slim has two digests (a moved tag -> history); the older digest
            # was superseded only just now, so it is retained but not aging out.
            "python:3.13.14-slim": _tag(
                _entry("a1", t=_at(0), total=3),
                _entry("a2", t=_at(175), total=5),
            ),
            "python:3.13.14": _tag(_entry("a3", t=_at(0), total=1)),
            "python:3.12.7-slim": _tag(
                _entry("a4", t=_at(10)),
                _entry("a5", t=_at(200)),
            ),
            # The dotnet head replaced its predecessor 170 days ago, so the predecessor is
            # past the default aging-out window.
            "mcr.microsoft.com/dotnet/sdk:8.0": _tag(
                _entry("b1", t=_at(170), total=2),
                _entry("b2", t=_at(175)),
            ),
            "ubuntu:24.04": _tag(_entry("c1", t=_at(0), total=7)),
            # An unknown image lands in the "other" bucket.
            "foo/unknown:1.0": _tag(_entry("x1", t=_at(0), total=1)),
        },
    }


def _stats():
    return compute_stats(_payload(), source="file", now=NOW)


def _image(stats, key):
    return next(image for image in stats.by_image if image.key == key)


# --------------------------------------------------------------------------- #
# compute_stats
# --------------------------------------------------------------------------- #


def test_totals_active_and_retained():
    stats = _stats()
    assert stats.total_digests == 9
    assert stats.distinct_tags == 6
    # One current pin (history head) per tag is active; the rest are retained history.
    assert stats.active_digests == 6
    assert stats.retained_digests == 3
    assert stats.sbom_count == 9


def test_per_tag_depth():
    stats = _stats()
    assert stats.per_tag_min == 1
    assert stats.per_tag_max == 2
    assert stats.per_tag_avg == 1.5


def test_created_range():
    stats = _stats()
    assert stats.oldest_created_at == NOW - timedelta(days=200)
    assert stats.newest_created_at == NOW


def test_aging_out_counts_only_past_cutoff():
    # Default window: 180 - 14 = 166 days. Only b2 (superseded 170 days ago) qualifies.
    stats = _stats()
    assert stats.aging_out_count == 1


def test_aging_within_widens_the_window():
    # A 9-day window means 180 - 9 = 171 days; b2's 170-day-old supersession no longer qualifies.
    stats = compute_stats(_payload(), source="file", now=NOW, aging_within_days=9)
    assert stats.aging_out_count == 0


def test_head_never_ages_out_however_old():
    # python:3.13.14-slim's head (a1) is the live pin; a2 was superseded just now (a1.t), so
    # neither ages out despite a2 being created 175 days ago.
    stats = _stats()
    # Only the dotnet predecessor ages out, confirming heads and just-superseded entries don't.
    assert stats.aging_out_count == 1


def test_by_image_grouping_and_counts():
    stats = _stats()
    python = _image(stats, "python")
    assert python.category == "language"
    assert python.tags == 3
    assert python.digests == 5
    versions = {v.version: (v.tags, v.digests) for v in python.versions}
    assert versions == {"3.13": (2, 3), "3.12": (1, 2)}
    # Versions are ordered newest-first.
    assert [v.version for v in python.versions] == ["3.13", "3.12"]


def test_by_image_orders_languages_then_os_then_other():
    stats = _stats()
    keys = [image.key for image in stats.by_image]
    assert keys.index("python") < keys.index("ubuntu") < keys.index("other")


def test_other_bucket_collects_unknown_references():
    other = _image(_stats(), "other")
    assert other.label == "Other"
    assert other.category == "other"
    assert other.tags == 1
    assert other.digests == 1


def test_calver_and_major_versions_use_the_raw_token():
    stats = _stats()
    assert [v.version for v in _image(stats, "ubuntu").versions] == ["24.04"]
    assert [v.version for v in _image(stats, "dotnet").versions] == ["8.0"]


def test_unparseable_versions_sort_after_real_ones():
    payload = {
        "schema_version": 3,
        "tags": {
            "python:latest": _tag(_entry("p1", t=_at(0))),
            "python:3.13.1-slim": _tag(_entry("p2", t=_at(0))),
            "python:3.9.1": _tag(_entry("p3", t=_at(0))),
        },
    }
    stats = compute_stats(payload, source="file", now=NOW)
    # Real versions stay newest-first; the unparseable "latest" token lands last.
    assert [v.version for v in _image(stats, "python").versions] == ["3.13", "3.9", "latest"]


def test_empty_report_is_safe():
    stats = compute_stats({"tags": {}}, source="local", now=NOW)
    assert stats.total_digests == 0
    assert stats.active_digests == 0
    assert stats.per_tag_avg == 0.0
    assert stats.by_image == []


def test_undated_entries_are_ignored_for_created_range():
    payload = {"schema_version": 3, "tags": {"python:3.13.1": _tag(_entry("z", t=None))}}
    stats = compute_stats(payload, source="file", now=NOW)
    # An entry with no created-at contributes no timestamp to the range.
    assert stats.oldest_created_at is None
    assert stats.newest_created_at is None
    assert stats.total_digests == 1


# --------------------------------------------------------------------------- #
# stats_payload (JSON shape)
# --------------------------------------------------------------------------- #


def test_stats_payload_shape():
    payload = stats_payload(_stats())
    assert payload["digests"] == {"total": 9, "active": 6, "retained": 3}
    assert payload["tags"]["distinct"] == 6
    assert payload["retention"]["aging_out"] == 1
    assert payload["sboms"]["published"] == 9
    assert payload["activity"]["newest_created_at"] == NOW.isoformat()
    python = next(i for i in payload["by_image"] if i["key"] == "python")
    assert python["versions"][0] == {"version": "3.13", "tags": 2, "digests": 3}


# --------------------------------------------------------------------------- #
# load_payload (sources)
# --------------------------------------------------------------------------- #


def test_load_payload_local(monkeypatch):
    monkeypatch.setattr(report_module, "_load_packaged", lambda: _payload())
    assert load_payload(source="local", report_path=None) is not None


@respx.mock
def test_load_payload_url(monkeypatch, tmp_path):
    url = "https://example.test/report.json"
    monkeypatch.setenv("IMAGE_INSPECTOR_REPORT_URL", url)
    monkeypatch.setenv("IMAGE_INSPECTOR_CACHE_DIR", str(tmp_path / "cache"))
    respx.get(url).mock(return_value=httpx.Response(200, json=_payload()))
    loaded = load_payload(source="url", report_path=None)
    assert loaded is not None
    assert loaded["trivy_version"] == "0.58.0"


def test_load_payload_from_file(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    loaded = load_payload(source="url", report_path=str(path))
    assert loaded is not None
    assert loaded["schema_version"] == 3


def test_load_payload_missing_file(tmp_path):
    assert load_payload(source="url", report_path=str(tmp_path / "nope.json")) is None


# --------------------------------------------------------------------------- #
# main (CLI)
# --------------------------------------------------------------------------- #


def _write_report(tmp_path) -> str:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    return str(path)


def test_main_json_output(tmp_path, capsys):
    code = main(["--report", _write_report(tmp_path), "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["source"] == "file"
    assert data["digests"]["total"] == 9


def test_main_rich_output(tmp_path, capsys):
    code = main(["--report", _write_report(tmp_path)])
    assert code == 0
    assert "database stats" in capsys.readouterr().out


def test_main_plain_output(tmp_path, capsys):
    code = main(["--report", _write_report(tmp_path), "--plain"])
    assert code == 0
    out = capsys.readouterr().out
    assert "BY IMAGE" in out
    assert "Python" in out


def test_main_missing_report_returns_1(tmp_path, capsys):
    code = main(["--report", str(tmp_path / "missing.json")])
    assert code == 1
    assert "Could not load" in capsys.readouterr().out


def test_main_rejects_negative_aging(capsys):
    code = main(["--source", "local", "--aging-within", "-1"])
    assert code == 2
    assert "zero or greater" in capsys.readouterr().out


def test_main_local_source_failure_returns_1(monkeypatch, capsys):
    monkeypatch.setattr(report_module, "_load_packaged", lambda: None)
    code = main(["--source", "local"])
    assert code == 1


def test_main_url_source(monkeypatch, capsys):
    monkeypatch.setattr(stats_module, "_load_url_payload", _payload)
    code = main(["--source", "url", "--plain"])
    assert code == 0
    assert "DIGESTS" in capsys.readouterr().out
