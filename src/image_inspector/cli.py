"""Entry point: orchestrate the language -> version -> variant selection flow."""

from __future__ import annotations

from . import ui
from .models import LANGUAGES, Language, ResolvedImage
from .registry import RegistryError, RegistryProvider, get_provider, make_client
from .versions import (
    is_ubuntu_lts,
    select_versions,
    tag_for_selection,
    variants_for_version,
)

MINOR_VERSION_COUNT = 5


def _lts_versions(language: Language, versions: list[str]) -> frozenset[str]:
    """Return the subset of ``versions`` that are LTS releases for ``language``."""
    if not language.marks_lts:
        return frozenset()
    return frozenset(v for v in versions if is_ubuntu_lts(v))


def _run(provider: RegistryProvider, language: Language) -> int:
    with ui.working(f"Fetching {language.label} tags…"):
        tag_names = provider.list_tag_names(want_minors=MINOR_VERSION_COUNT)

    versions = select_versions(tag_names, language.scheme, count=MINOR_VERSION_COUNT)
    if not versions:
        ui.error(f"No semantic-version tags found for {language.label}.")
        return 1

    version = ui.select_version(versions, _lts_versions(language, versions))
    if version is None:
        ui.cancelled()
        return 130

    variants = variants_for_version(tag_names, version)
    if not variants:
        ui.error(f"No tags found for version {version}.")
        return 1

    if len(variants) == 1:
        variant = variants[0]
    else:
        variant = ui.select_variant(variants)
        if variant is None:
            ui.cancelled()
            return 130

    tag = tag_for_selection(version, variant)
    with ui.working(f"Resolving {language.image_name}:{tag}…"):
        image_tag = provider.resolve(tag)

    ui.show_result(
        ResolvedImage(
            language=language,
            tag=tag,
            digest=image_tag.digest,
            created=image_tag.last_updated,
            size=image_tag.size,
        )
    )
    return 0


def main() -> int:
    """CLI entry point. Returns a process exit code."""
    ui.banner()

    language = ui.select_language(LANGUAGES)
    if language is None:
        ui.cancelled()
        return 130

    try:
        with make_client() as client:
            provider = get_provider(language, client)
            return _run(provider, language)
    except RegistryError as exc:
        ui.error(str(exc))
        return 1
    except KeyboardInterrupt:
        ui.cancelled()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
