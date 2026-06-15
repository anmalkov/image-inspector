"""Flow test for the CLI: prompts and network are stubbed out."""

from contextlib import contextmanager
from datetime import UTC, datetime

from image_inspector import cli, ui
from image_inspector.models import LANGUAGES_BY_KEY, ImageTag


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

    captured = {}
    monkeypatch.setattr(ui, "show_result", lambda image: captured.update(image=image))

    assert cli.main() == 0
    assert fake.resolved_tag == "3.13.14-slim"
    assert captured["image"].pinned_reference == "python:3.13.14-slim@sha256:deadbeef"
    assert captured["image"].size == 12345


def test_main_cancel_language(monkeypatch):
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: None)
    assert cli.main() == 130


def test_main_cancel_version(monkeypatch):
    python = LANGUAGES_BY_KEY["python"]
    monkeypatch.setattr(cli, "make_client", _fake_client)
    monkeypatch.setattr(cli, "get_provider", lambda lang, client: FakeProvider())
    monkeypatch.setattr(ui, "banner", lambda: None)
    monkeypatch.setattr(ui, "select_language", lambda languages: python)
    monkeypatch.setattr(ui, "select_version", lambda versions, lts=frozenset(): None)
    assert cli.main() == 130


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

    assert cli.main() == 0
    assert fake.resolved_tag == "3.12.13"
