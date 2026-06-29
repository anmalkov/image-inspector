"""Unit tests for UI helpers."""

from datetime import UTC, datetime

from image_inspector.inspection import inspect_dockerfile
from image_inspector.models import LANGUAGES_BY_KEY, ResolvedImage, ScanSource
from image_inspector.report import (
    DetailsReport,
    ImageVulnerabilities,
    ReportSource,
    Vulnerability,
    VulnerabilityReport,
)
from image_inspector.ui import (
    Installer,
    _is_newer,
    configure,
    copy_to_clipboard,
    detect_installer,
    dockerfile_payload,
    format_data_source,
    format_datetime,
    format_outdated_warning,
    format_scan_source,
    format_size,
    format_update_notice,
    format_vulnerabilities,
    render_dockerfile_inspection,
    result_payload,
    show_version_status,
    upgrade_command,
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
    # Counts only; the scanned timestamp is now a separate SECURITY row.
    assert text.plain == "Critical: 1  ·  High: 2  ·  Total: 10"


def test_format_scan_source_full():
    source = ScanSource(version="0.71.1", db_updated_at=datetime(2026, 6, 14, tzinfo=UTC))
    assert format_scan_source(source) == "Trivy v0.71.1 · DB Jun 14, 2026"


def test_format_scan_source_without_db_date():
    assert format_scan_source(ScanSource(version="0.71.1")) == "Trivy v0.71.1"


def test_format_scan_source_none():
    assert format_scan_source(None) is None
    assert format_scan_source(ScanSource(version=None)) is None


def test_format_data_source_values():
    assert format_data_source(ReportSource.ONLINE) == "online (latest)"
    assert format_data_source(ReportSource.OFFLINE) == "offline (bundled copy)"
    assert format_data_source(ReportSource.OUTDATED) == "bundled (tool outdated)"
    assert format_data_source(None) == "not found"


def test_detect_installer_uv_tool():
    assert detect_installer("/x/uv/tools/p/site-packages/ui.py") is Installer.UV_TOOL


def test_detect_installer_uvx_cache():
    assert detect_installer("/x/uv/cache/archive-v0/h/site-packages/ui.py") is Installer.UVX


def test_detect_installer_uvx_cache_windows():
    path = r"C:\Users\u\AppData\Local\uv\cache\archive-v0\h\Lib\site-packages\ui.py"
    assert detect_installer(path) is Installer.UVX


def test_detect_installer_pipx():
    assert detect_installer("/home/u/.local/pipx/venvs/p/lib/ui.py") is Installer.PIPX


def test_detect_installer_pip_fallback():
    assert detect_installer("/home/u/project/.venv/lib/site-packages/ui.py") is Installer.PIP


def test_upgrade_command_matches_installer():
    assert upgrade_command("/x/uv/tools/p/ui.py") == "uv tool upgrade base-image-inspector"
    assert upgrade_command("/x/pipx/venvs/p/ui.py") == "pipx upgrade base-image-inspector"
    assert upgrade_command("/x/.venv/lib/ui.py") == "pip install --upgrade base-image-inspector"
    assert (
        upgrade_command("/x/uv/cache/archive-v0/h/ui.py")
        == "uvx --from base-image-inspector@latest image-inspector"
    )


def test_is_newer():
    assert _is_newer("0.2.1", "0.1.0") is True
    assert _is_newer("0.1.0", "0.1.0") is False
    assert _is_newer("0.1.0", "0.2.1") is False
    assert _is_newer(None, "0.1.0") is False
    assert _is_newer("not-a-version", "0.1.0") is False


def test_format_update_notice_when_newer():
    notice = format_update_notice("0.1.0", "0.2.1")
    assert notice is not None
    assert "0.2.1" in notice.plain
    assert "base-image-inspector" in notice.plain


def test_format_update_notice_none_when_current_or_unknown():
    assert format_update_notice("0.2.1", "0.2.1") is None
    assert format_update_notice("0.2.1", None) is None
    assert format_update_notice("0.2.1", "0.1.0") is None


def test_format_outdated_warning_update_available():
    text = format_outdated_warning(datetime(2026, 6, 15, tzinfo=UTC), "0.1.0", "0.2.1").plain
    assert "outdated" in text.lower()
    assert "Jun 15, 2026" in text
    assert "0.2.1" in text  # available version
    assert "base-image-inspector" in text  # installer-aware upgrade command


def test_format_outdated_warning_coming_soon():
    # latest unknown (PyPI unreachable) -> 'coming soon', never an upgrade command.
    text = format_outdated_warning(datetime(2026, 6, 15, tzinfo=UTC), "0.2.1", None).plain
    assert "available soon" in text.lower()
    assert "upgrade" not in text.lower()


def test_format_outdated_warning_coming_soon_when_not_newer():
    # latest == installed (matching release not published yet) -> 'coming soon'.
    text = format_outdated_warning(None, "0.2.1", "0.2.1").plain
    assert "available soon" in text.lower()


def test_show_version_status_outdated_prints(capsys):
    show_version_status(ReportSource.OUTDATED, datetime(2026, 6, 15, tzinfo=UTC), "0.1.0", "0.2.1")
    out = capsys.readouterr().out
    assert "outdated" in out.lower()
    assert "0.2.1" in out


def test_show_version_status_update_notice(capsys):
    show_version_status(ReportSource.ONLINE, None, "0.1.0", "0.2.1")
    out = capsys.readouterr().out.lower()
    assert "update available" in out
    assert "0.2.1" in out


def test_show_version_status_silent_when_current(capsys):
    show_version_status(ReportSource.ONLINE, None, "0.2.1", "0.2.1")
    assert capsys.readouterr().out.strip() == ""


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
        scan_source=ScanSource(version="0.71.1", db_updated_at=datetime(2026, 6, 14, tzinfo=UTC)),
        report_source=ReportSource.ONLINE,
    )
    payload = result_payload(image)
    assert payload["language"] == "python"
    assert payload["version"] == "3.13.14"
    assert payload["variant"] == "slim"
    assert payload["pinned_reference"] == "python:3.13.14-slim@sha256:deadbeef"
    assert payload["from_line"] == "FROM python:3.13.14-slim@sha256:deadbeef"
    assert payload["vulnerabilities"]["high"] == 2
    assert payload["data_source"] == "online"
    assert payload["scanner"] == {
        "name": "trivy",
        "version": "0.71.1",
        "db_updated_at": "2026-06-14T00:00:00+00:00",
    }


def test_result_payload_scanner_null_when_unscanned():
    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    payload = result_payload(image)
    assert payload["scanner"] == {"name": "trivy", "version": None, "db_updated_at": None}
    assert payload["data_source"] is None


def test_result_sections_structure():
    from image_inspector.ui import _result_sections

    image = _resolved(
        language=LANGUAGES_BY_KEY["python"],
        tag="3.13.14-alpine",
        version="3.13.14",
        variant="alpine",
        vulnerabilities=ImageVulnerabilities(
            critical=1, high=2, total=7, scanned_at=datetime(2026, 6, 15, tzinfo=UTC)
        ),
        scan_source=ScanSource(version="0.71.1", db_updated_at=datetime(2026, 6, 14, tzinfo=UTC)),
        report_source=ReportSource.ONLINE,
    )
    sections = _result_sections(image)
    titles = [title for title, _ in sections]
    assert titles == ["SELECTED", "IMAGE", "SECURITY"]

    security = next(rows for title, rows in sections if title == "SECURITY")
    labels = {label: value for label, value in security}
    assert set(labels) == {"Vulnerabilities", "Scanned", "Scanner", "Source"}
    assert labels["Scanner"] == "Trivy v0.71.1 · DB Jun 14, 2026"
    assert labels["Source"] == "online (latest)"


def test_result_sections_security_omits_unknown_rows():
    from image_inspector.ui import _result_sections

    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    security = next(rows for title, rows in _result_sections(image) if title == "SECURITY")
    # No scan data and no report: only Vulnerabilities plus the always-shown Source row.
    assert [label for label, _ in security] == ["Vulnerabilities", "Source"]
    assert dict(security)["Source"] == "not found"


def test_copy_to_clipboard_emits_osc52(capsys):
    copy_to_clipboard("FROM ubuntu:24.04")
    out = capsys.readouterr().out
    # base64 of "FROM ubuntu:24.04"
    assert out == "\033]52;c;RlJPTSB1YnVudHU6MjQuMDQ=\a"


# --- selected-image critical/high CVE detail ------------------------------------------------


def _vulnerable_image(**kwargs) -> ResolvedImage:
    """A resolved image carrying critical/high CVE detail for the SECURITY panel."""
    base = dict(
        language=LANGUAGES_BY_KEY["python"],
        tag="3.13.14-slim",
        digest="sha256:deadbeef",
        created=datetime(2026, 6, 1, tzinfo=UTC),
        version="3.13.14",
        variant="slim",
        vulnerabilities=ImageVulnerabilities(critical=1, high=1, total=8),
        cve_details=(
            Vulnerability("CVE-2025-1", "openssl", "C", "3.3.2"),
            Vulnerability("CVE-2025-2", "zlib", "H", None),
        ),
        report_source=ReportSource.ONLINE,
    )
    base.update(kwargs)
    return ResolvedImage(**base)


def test_result_sections_lists_critical_high_cves():
    from image_inspector.ui import _result_sections

    security = next(
        rows for title, rows in _result_sections(_vulnerable_image()) if title == "SECURITY"
    )
    value = next(v for label, v in security if label == "CVEs")
    rendered = value.plain
    assert "SEVERITY" in rendered and "PACKAGE" in rendered and "FIX" in rendered
    assert "critical  CVE-2025-1  openssl  upgrade to 3.3.2" in rendered
    assert "high      CVE-2025-2  zlib     no fix yet" in rendered


def test_result_sections_omit_cves_when_clean():
    from image_inspector.ui import _result_sections

    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    security = next(rows for title, rows in _result_sections(image) if title == "SECURITY")
    assert all(label != "CVEs" for label, _ in security)


def test_result_payload_includes_critical_high_cves():
    payload = result_payload(_vulnerable_image())
    assert payload["critical_high_cves"] == [
        {
            "id": "CVE-2025-1",
            "package": "openssl",
            "severity": "critical",
            "fixed_version": "3.3.2",
        },
        {"id": "CVE-2025-2", "package": "zlib", "severity": "high", "fixed_version": None},
    ]


def test_result_payload_critical_high_cves_empty_when_clean():
    image = _resolved(language=LANGUAGES_BY_KEY["python"], tag="3.13.14", version="3.13.14")
    assert result_payload(image)["critical_high_cves"] == []


# --- Dockerfile diff rendering + --json -----------------------------------------------------

_PINNED = "pinneddigest"
_LATEST = "latestdigest"


def _dockerfile_report() -> VulnerabilityReport:
    return VulnerabilityReport.from_dict(
        {
            "schema_version": 3,
            "generated_at": "2026-06-15T02:00:00Z",
            "trivy_version": "0.71.1",
            "trivy_db_updated_at": "2026-06-14T00:00:00Z",
            "tags": {
                "python:3.13-slim": {
                    "history": [
                        {"d": _LATEST, "t": "2026-06-14T07:00:00Z", "c": [0, 1, 2, 3, 0]},
                        {"d": _PINNED, "t": "2026-06-01T07:00:00Z", "c": [2, 5, 10, 20, 3]},
                    ]
                }
            },
        }
    )


def _dockerfile_details() -> DetailsReport:
    return DetailsReport.from_dict(
        {
            "schema_version": 3,
            "vulns": [
                {"id": "CVE-A", "pkg": "openssl", "sev": "C", "fix": "3.3.2"},
                {"id": "CVE-B", "pkg": "zlib", "sev": "H", "fix": None},
                {"id": "CVE-C", "pkg": "glibc", "sev": "C", "fix": "2.40"},
            ],
            "digests": {_PINNED: [0, 1, 2], _LATEST: [1]},
        }
    )


_DOCKERFILE = f"FROM python:3.13-slim@sha256:{_PINNED} AS build\nFROM scratch\nFROM ubuntu:99.99\n"


def _dockerfile_inspections():
    return inspect_dockerfile(_DOCKERFILE, _dockerfile_report(), _dockerfile_details())


def test_render_dockerfile_inspection_rich(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    configure(plain=False)
    render_dockerfile_inspection(_dockerfile_inspections())
    out = capsys.readouterr().out
    assert "3 FROM stage(s)" in out
    assert "FROM python:3.13-slim" in out
    assert "cleaner" in out
    assert "latest fixes 2 of your critical/high CVE(s)" in out
    assert "CVE-A" in out and "CVE-C" in out  # fixed
    assert "CVE-B" in out  # still present
    assert "33 → 5" in out  # medium/low/unknown movement (10+20+3 -> 2+3+0)
    assert "critical/high only" in out
    assert "not tracked" in out  # the untracked stages


def test_render_dockerfile_inspection_plain(capsys, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    configure(plain=True)
    render_dockerfile_inspection(_dockerfile_inspections())
    out = capsys.readouterr().out
    configure(plain=False)
    assert "FROM python:3.13-slim" in out
    assert "fixed in 3.3.2" in out
    assert "33 → 5" in out


def test_render_dockerfile_inspection_empty(capsys):
    configure(plain=False)
    render_dockerfile_inspection([])
    assert "No FROM instructions found." in capsys.readouterr().out


def test_dockerfile_payload_pinned_known_stage():
    payload = dockerfile_payload("Dockerfile", _dockerfile_inspections(), _dockerfile_report())
    assert payload["dockerfile"] == "Dockerfile"
    assert payload["stage_count"] == 3
    assert payload["data_source"] is None  # report built via from_dict has no source set
    assert payload["scanner"] == {
        "name": "trivy",
        "version": "0.71.1",
        "db_updated_at": "2026-06-14T00:00:00+00:00",
    }

    stage = payload["stages"][0]
    assert stage["status"] == "pinned_known"
    assert stage["alias"] == "build"
    assert stage["pinned"]["digest"] == f"sha256:{_PINNED}"
    assert stage["latest"]["digest"] == f"sha256:{_LATEST}"
    assert stage["pinned"]["vulnerabilities"]["critical"] == 2
    assert stage["latest"]["vulnerabilities"]["high"] == 1
    assert stage["critical_high"]["detail_scope"] == "critical_high_only"
    assert {c["id"] for c in stage["critical_high"]["fixed"]} == {"CVE-A", "CVE-C"}
    fixed_a = next(c for c in stage["critical_high"]["fixed"] if c["id"] == "CVE-A")
    assert fixed_a == {
        "id": "CVE-A",
        "package": "openssl",
        "severity": "critical",
        "fixed_version": "3.3.2",
    }
    assert [c["id"] for c in stage["critical_high"]["still_present"]] == ["CVE-B"]
    assert stage["flags"] == {
        "has_data": True,
        "pinned_vulnerable": True,
        "latest_is_cleaner": True,
    }


def test_dockerfile_payload_untracked_stage_flags():
    payload = dockerfile_payload("Dockerfile", _dockerfile_inspections(), _dockerfile_report())
    untracked = payload["stages"][2]
    assert untracked["status"] == "untracked"
    assert untracked["pinned"]["vulnerabilities"] is None
    assert untracked["latest"]["vulnerabilities"] is None
    assert untracked["flags"] == {
        "has_data": False,
        "pinned_vulnerable": False,
        "latest_is_cleaner": False,
    }
