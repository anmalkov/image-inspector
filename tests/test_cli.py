"""Flow test for the CLI: prompts and network are stubbed out."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime

from image_inspector import cli, ui
from image_inspector.models import LANGUAGES_BY_KEY, ImageTag
from image_inspector.report import ImageVulnerabilities, VulnerabilityReport


class FakeProvider:
    def __init__(self):
        self.resolved_tag = None

    def list_tag_names(self, *, want_minors):
        return ["3.13.14", "3.12.13", "3.13.14-slim"]

    def resolve(self, tag):
        self.resolved_tag = tag
        return ImageTag(
            name=tag,
            digest="sha256:deadbeef",
            last_updated=datetime(2026, 6, 11, 8, 0, 0, tzinfo=UTC),
            size=12345,
        )


@contextmanager
def _fake_client():
    yield object()


def test_main_happy_path(monkeypatch):
    fake = FakeProvider()
    python = LANGUAGES_BY_KEY["python"]

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): "3.13.14")
    monkeypatch.setattr(ui, "select_variant", lambda variants: "slim")
    monkeypatch.setattr(ui, "result_actions", lambda image: False)

    captured = {}
    monkeypatch.setattr(ui, "show_result", lambda image: captured.update(image=image))

    assert cli.main([]) == 0
    assert fake.resolved_tag == "3.13.14-slim"
    assert captured["image"].pinned_reference == "python:3.13.14-slim@sha256:deadbeef"
    assert captured["image"].size == 12345


def test_main_attaches_vulnerabilities_from_report(monkeypatch):
    fake = FakeProvider()
    python = LANGUAGES_BY_KEY["python"]
    report = VulnerabilityReport(
        images={"deadbeef": ImageVulnerabilities(critical=1, high=2, total=7)}
    )

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(cli, "load_report", lambda: report)
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): "3.13.14")
    monkeypatch.setattr(ui, "select_variant", lambda variants: "slim")
    monkeypatch.setattr(ui, "result_actions", lambda image: False)

    captured = {}
    monkeypatch.setattr(ui, "show_result", lambda image: captured.update(image=image))

    assert cli.main([]) == 0
    assert captured["image"].vulnerabilities == ImageVulnerabilities(critical=1, high=2, total=7)


def test_main_threads_scan_source_from_report(monkeypatch):
    fake = FakeProvider()
    python = LANGUAGES_BY_KEY["python"]
    report = VulnerabilityReport(
        trivy_version="0.71.1",
        trivy_db_updated_at=datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC),
        images={"deadbeef": ImageVulnerabilities(critical=1, high=2, total=7)},
    )

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(cli, "load_report", lambda: report)
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): "3.13.14")
    monkeypatch.setattr(ui, "select_variant", lambda variants: "slim")
    monkeypatch.setattr(ui, "result_actions", lambda image: False)

    captured = {}
    monkeypatch.setattr(ui, "show_result", lambda image: captured.update(image=image))

    assert cli.main([]) == 0
    source = captured["image"].scan_source
    assert source.version == "0.71.1"
    assert source.db_updated_at == datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC)


def test_main_cancel_language(monkeypatch):
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: None)
    assert cli.main([]) == 130


def test_main_cancel_version(monkeypatch):
    python = LANGUAGES_BY_KEY["python"]
    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: FakeProvider())
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): None)
    assert cli.main([]) == 130


def test_main_skips_variant_prompt_when_single_variant(monkeypatch):
    fake = FakeProvider()
    python = LANGUAGES_BY_KEY["python"]

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    # 3.12.13 has only the plain variant, so the variant prompt must be skipped.
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): "3.12.13")

    def _fail_variant(variants):
        raise AssertionError("select_variant should not be called for a single variant")

    monkeypatch.setattr(ui, "select_variant", _fail_variant)
    monkeypatch.setattr(ui, "show_result", lambda image: None)
    monkeypatch.setattr(ui, "result_actions", lambda image: False)

    assert cli.main([]) == 0
    assert fake.resolved_tag == "3.12.13"


def test_main_new_selection_loops(monkeypatch):
    fake = FakeProvider()
    python = LANGUAGES_BY_KEY["python"]

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): "3.12.13")
    monkeypatch.setattr(ui, "show_result", lambda image: None)

    # First action asks for a new selection, second exits.
    actions = iter([True, False])
    monkeypatch.setattr(ui, "result_actions", lambda image: next(actions))

    assert cli.main([]) == 0


def test_main_json_non_interactive(monkeypatch, capsys):
    fake = FakeProvider()
    report = VulnerabilityReport(
        trivy_version="0.71.1",
        trivy_db_updated_at=datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC),
        images={"deadbeef": ImageVulnerabilities(critical=1, high=2, total=7)},
    )

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(cli, "load_report", lambda: report)

    rc = cli.main(["--json", "-l", "python", "--version", "3.13.14", "--variant", "slim"])
    assert rc == 0
    assert fake.resolved_tag == "3.13.14-slim"

    payload = json.loads(capsys.readouterr().out)
    assert payload["pinned_reference"] == "python:3.13.14-slim@sha256:deadbeef"
    assert payload["vulnerabilities"]["high"] == 2
    assert payload["scanner"] == {
        "name": "trivy",
        "version": "0.71.1",
        "db_updated_at": "2026-06-14T12:00:00+00:00",
    }


def test_main_json_requires_version(monkeypatch):
    rc = cli.main(["--json", "-l", "python"])
    assert rc == 2


def test_main_json_includes_critical_high_cves(monkeypatch, capsys):
    from image_inspector.report import DetailsReport

    fake = FakeProvider()
    report = VulnerabilityReport(
        images={"deadbeef": ImageVulnerabilities(critical=1, high=1, total=5)},
    )
    details = DetailsReport.from_dict(
        {
            "schema_version": 3,
            "vulns": [
                {"id": "CVE-A", "pkg": "openssl", "sev": "C", "fix": "3.3.2"},
                {"id": "CVE-B", "pkg": "zlib", "sev": "H", "fix": None},
            ],
            "digests": {"deadbeef": [0, 1]},
        }
    )

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(cli, "load_report", lambda: report)
    monkeypatch.setattr(cli, "load_details", lambda: details)

    rc = cli.main(["--json", "-l", "python", "--version", "3.13.14", "--variant", "slim"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["critical_high_cves"] == [
        {"id": "CVE-A", "package": "openssl", "severity": "critical", "fixed_version": "3.3.2"},
        {"id": "CVE-B", "package": "zlib", "severity": "high", "fixed_version": None},
    ]


def test_main_json_skips_details_for_clean_image(monkeypatch, capsys):
    fake = FakeProvider()
    report = VulnerabilityReport(
        images={"deadbeef": ImageVulnerabilities(critical=0, high=0, medium=3, total=3)},
    )

    def _boom() -> object:
        raise AssertionError("load_details must not be called for a clean image")

    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: fake)
    monkeypatch.setattr(cli, "load_report", lambda: report)
    monkeypatch.setattr(cli, "load_details", _boom)

    rc = cli.main(["--json", "-l", "python", "--version", "3.13.14", "--variant", "slim"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["critical_high_cves"] == []


def test_main_dockerfile_json(monkeypatch, capsys, tmp_path):
    from image_inspector.report import DetailsReport

    pinned, latest = "pinneddigest", "latestdigest"
    report = VulnerabilityReport.from_dict(
        {
            "schema_version": 3,
            "generated_at": "2026-06-15T02:00:00Z",
            "trivy_version": "0.71.1",
            "tags": {
                "python:3.13-slim": {
                    "history": [
                        {"d": latest, "t": "2026-06-14T07:00:00Z", "c": [0, 1, 2, 3, 0]},
                        {"d": pinned, "t": "2026-06-01T07:00:00Z", "c": [2, 5, 10, 20, 3]},
                    ]
                }
            },
        }
    )
    details = DetailsReport.from_dict(
        {
            "schema_version": 3,
            "vulns": [
                {"id": "CVE-A", "pkg": "openssl", "sev": "C", "fix": "3.3.2"},
                {"id": "CVE-B", "pkg": "zlib", "sev": "H", "fix": None},
            ],
            "digests": {pinned: [0, 1], latest: [1]},
        }
    )
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(f"FROM python:3.13-slim@sha256:{pinned}\n", encoding="utf-8")

    monkeypatch.setattr(cli, "load_report", lambda: report)
    monkeypatch.setattr(cli, "load_details", lambda: details)

    rc = cli.main(["--dockerfile", str(dockerfile), "--json"])
    assert rc == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["stage_count"] == 1
    assert payload["scanner"]["version"] == "0.71.1"
    stage = payload["stages"][0]
    assert stage["status"] == "pinned_known"
    assert stage["pinned"]["digest"] == f"sha256:{pinned}"
    assert stage["latest"]["digest"] == f"sha256:{latest}"
    assert [c["id"] for c in stage["critical_high"]["fixed"]] == ["CVE-A"]
    assert [c["id"] for c in stage["critical_high"]["still_present"]] == ["CVE-B"]
    assert stage["flags"]["latest_is_cleaner"] is True


def test_main_dockerfile_unreadable_path():
    rc = cli.main(["--dockerfile", "does-not-exist.Dockerfile", "--json"])
    assert rc == 2
