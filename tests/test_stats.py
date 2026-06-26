"""Tests for the dev-only database stats view."""

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


def _payload() -> dict:
    return {
        "schema_version": 2,
        "generated_at": "2026-06-25T02:14:03Z",
        "trivy_version": "0.58.0",
        "trivy_db_updated_at": "2026-06-25T01:30:00Z",
        "images": {
            # python:3.13.14-slim has two digests (a moved tag -> history).
            "sha256:a1": {"reference": "python:3.13.14-slim", "total": 3, "last_active_at": _at(0)},
            "sha256:a2": {
                "reference": "python:3.13.14-slim",
                "total": 5,
                "last_active_at": _at(170),
            },
            "sha256:a3": {"reference": "python:3.13.14", "total": 1, "last_active_at": _at(0)},
            "sha256:a4": {"reference": "python:3.12.7-slim", "total": 0, "last_active_at": _at(10)},
            "sha256:b1": {
                "reference": "mcr.microsoft.com/dotnet/sdk:8.0",
                "total": 2,
                "last_active_at": _at(0),
            },
            "sha256:c1": {"reference": "ubuntu:24.04", "total": 7, "last_active_at": _at(0)},
            # An unknown image lands in the "other" bucket.
            "sha256:x1": {"reference": "foo/unknown:1.0", "total": 1, "last_active_at": _at(0)},
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
    assert stats.total_digests == 7
    assert stats.distinct_tags == 6
    # One current pin per tag is active; the extra python:3.13.14-slim digest is history.
    assert stats.active_digests == 6
    assert stats.retained_digests == 1
    assert stats.sbom_count == 7


def test_per_tag_depth():
    stats = _stats()
    assert stats.per_tag_min == 1
    assert stats.per_tag_max == 2
    assert stats.per_tag_avg == 1.2


def test_activity_range():
    stats = _stats()
    assert stats.oldest_active_at == NOW - timedelta(days=170)
    assert stats.newest_active_at == NOW


def test_aging_out_counts_only_near_cutoff():
    # Default window: 180 - 14 = 166 days. Only the 170-day-old digest qualifies.
    stats = _stats()
    assert stats.aging_out_count == 1


def test_aging_within_widens_the_window():
    # A 9-day window means 180 - 9 = 171 days; the 170-day digest no longer qualifies.
    stats = compute_stats(_payload(), source="file", now=NOW, aging_within_days=9)
    assert stats.aging_out_count == 0


def test_by_image_grouping_and_counts():
    stats = _stats()
    python = _image(stats, "python")
    assert python.category == "language"
    assert python.tags == 3
    assert python.digests == 4
    versions = {v.version: (v.tags, v.digests) for v in python.versions}
    assert versions == {"3.13": (2, 3), "3.12": (1, 1)}
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


def test_empty_report_is_safe():
    stats = compute_stats({"images": {}}, source="local", now=NOW)
    assert stats.total_digests == 0
    assert stats.active_digests == 0
    assert stats.per_tag_avg == 0.0
    assert stats.by_image == []


def test_scanned_at_is_used_when_last_active_missing():
    payload = {"images": {"sha256:z": {"reference": "python:3.13.1", "scanned_at": _at(0)}}}
    stats = compute_stats(payload, source="file", now=NOW)
    assert stats.newest_active_at == NOW


# --------------------------------------------------------------------------- #
# stats_payload (JSON shape)
# --------------------------------------------------------------------------- #


def test_stats_payload_shape():
    payload = stats_payload(_stats())
    assert payload["digests"] == {"total": 7, "active": 6, "retained": 1}
    assert payload["tags"]["distinct"] == 6
    assert payload["retention"]["aging_out"] == 1
    assert payload["sboms"]["published"] == 7
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
    assert loaded["schema_version"] == 2


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
    assert data["digests"]["total"] == 7


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
