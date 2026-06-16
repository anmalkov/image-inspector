"""Entry point: orchestrate the language -> version -> variant selection flow."""

from __future__ import annotations

import argparse

from . import __version__, ui
from .models import LANGUAGES, LANGUAGES_BY_KEY, Language, ResolvedImage
from .registry import RegistryError, RegistryProvider, get_provider, make_client
from .report import VulnerabilityReport, load_report
from .versions import (
    PLAIN_VARIANT,
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


def _display_variant(variant: str) -> str | None:
    """Map the plain-variant sentinel to ``None`` for display/serialisation."""
    return None if variant == PLAIN_VARIANT else variant


def _resolve(
    provider: RegistryProvider, language: Language, report: VulnerabilityReport
) -> ResolvedImage | None:
    """Run the interactive version/variant prompts. ``None`` means cancelled."""
    with ui.working(f"Fetching {language.label} tags…"):
        tag_names = provider.list_tag_names(want_minors=MINOR_VERSION_COUNT)

    versions = select_versions(tag_names, language.scheme, count=MINOR_VERSION_COUNT)
    if not versions:
        ui.error(f"No semantic-version tags found for {language.label}.")
        return None

    version = ui.select_version(versions, _lts_versions(language, versions))
    if version is None:
        return None

    variants = variants_for_version(tag_names, version)
    if not variants:
        ui.error(f"No tags found for version {version}.")
        return None

    if len(variants) == 1:
        variant = variants[0]
    else:
        variant = ui.select_variant(variants)
        if variant is None:
            return None

    tag = tag_for_selection(version, variant)
    with ui.working(f"Resolving {language.image_name}:{tag}…"):
        image_tag = provider.resolve(tag)

    return ResolvedImage(
        language=language,
        tag=tag,
        digest=image_tag.digest,
        created=image_tag.last_updated,
        size=image_tag.size,
        vulnerabilities=report.lookup(image_tag.digest),
        version=version,
        variant=_display_variant(variant),
        is_lts=bool(_lts_versions(language, [version])),
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="image-inspector",
        description="Interactively pick and digest-pin official container base images.",
        epilog=(
            "Examples:\n"
            "  image-inspector                 # interactive picker\n"
            "  image-inspector --no-banner     # skip the launch banner\n"
            "  image-inspector --plain         # uncolored, automation-friendly output\n"
            "  image-inspector --json -l ubuntu --version 24.04 --variant '(none)'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--app-version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the image-inspector version and exit",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="do not print the launch banner",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="plain, uncolored output (selection stays interactive)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="non-interactive JSON output; requires --language and --version",
    )
    parser.add_argument(
        "-l",
        "--language",
        choices=sorted(LANGUAGES_BY_KEY),
        help="language/image key to resolve (required with --json)",
    )
    parser.add_argument(
        "--version",
        dest="image_version",
        metavar="VERSION",
        help="image version to resolve, e.g. 3.13.14 or 24.04 (required with --json)",
    )
    parser.add_argument(
        "--variant",
        help="image variant, e.g. slim or alpine ('(none)' for the plain tag)",
    )
    return parser


def _choose_variant_for_json(requested: str | None, variants: list[str]) -> str | None:
    """Pick a variant for non-interactive use. ``None`` means the error was reported."""
    if requested is not None:
        if requested in variants:
            return requested
        ui.error(f"Unknown variant '{requested}'. Options: {', '.join(variants)}")
        return None
    if len(variants) == 1:
        return variants[0]
    if PLAIN_VARIANT in variants:
        return PLAIN_VARIANT
    ui.error(
        f"Multiple variants available; choose one with --variant. "
        f"Options: {', '.join(variants)}"
    )
    return None


def _run_json(args: argparse.Namespace, report: VulnerabilityReport) -> int:
    """Resolve an image non-interactively and print it as JSON."""
    if not args.language:
        ui.error("--json requires --language.")
        return 2
    if not args.image_version:
        ui.error("--json requires --version.")
        return 2

    language = LANGUAGES_BY_KEY[args.language]
    version = args.image_version
    try:
        with make_client() as client:
            provider = get_provider(language, client)
            tag_names = provider.list_tag_names(want_minors=MINOR_VERSION_COUNT)
            variants = variants_for_version(tag_names, version)
            if not variants:
                ui.error(f"No tags found for {language.label} version {version}.")
                return 1
            variant = _choose_variant_for_json(args.variant, variants)
            if variant is None:
                return 2
            tag = tag_for_selection(version, variant)
            image_tag = provider.resolve(tag)
    except RegistryError as exc:
        ui.error(str(exc))
        return 1

    image = ResolvedImage(
        language=language,
        tag=tag,
        digest=image_tag.digest,
        created=image_tag.last_updated,
        size=image_tag.size,
        vulnerabilities=report.lookup(image_tag.digest),
        version=version,
        variant=_display_variant(variant),
        is_lts=bool(_lts_versions(language, [version])),
    )
    ui.show_result_json(image)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    report = load_report()

    if args.json:
        return _run_json(args, report)

    ui.configure(plain=args.plain)
    if not args.no_banner:
        ui.banner()

    while True:
        language = ui.select_language(LANGUAGES)
        if language is None:
            ui.cancelled()
            return 130

        try:
            with make_client() as client:
                provider = get_provider(language, client)
                image = _resolve(provider, language, report)
        except RegistryError as exc:
            ui.error(str(exc))
            return 1
        except KeyboardInterrupt:
            ui.cancelled()
            return 130

        if image is None:
            ui.cancelled()
            return 130

        ui.show_result(image)

        if args.plain:
            return 0
        if ui.result_actions(image):
            continue
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
