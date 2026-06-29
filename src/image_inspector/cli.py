"""Entry point: orchestrate the language -> version -> variant selection flow."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__, ui
from .inspection import _sorted_vulns, inspect_dockerfile
from .models import LANGUAGES, LANGUAGES_BY_KEY, Language, ResolvedImage, ScanSource
from .registry import RegistryError, RegistryProvider, get_provider, make_client
from .report import (
    ImageVulnerabilities,
    Vulnerability,
    VulnerabilityReport,
    latest_pypi_version,
    load_details,
    load_report,
)
from .versions import (
    PLAIN_VARIANT,
    is_ubuntu_lts,
    select_versions,
    tag_for_selection,
    variants_for_version,
)

MINOR_VERSION_COUNT = 5


def _critical_high_cves(
    vulns: ImageVulnerabilities | None, digest: str | None
) -> tuple[Vulnerability, ...]:
    """Return the image's critical/high CVEs, loading the details sidecar only when needed.

    The lookup is skipped entirely (returning no CVEs) when the image has zero critical and
    zero high findings, so the always-on selection path never fetches the details sidecar for
    a clean image. CVEs are ordered critical-first, then by id, to match the fix-diff lists.
    """
    if vulns is None or (vulns.critical == 0 and vulns.high == 0):
        return ()
    return _sorted_vulns(load_details().cve_set(digest))


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
        selected = ui.select_variant(variants)
        if selected is None:
            return None
        variant = selected

    tag = tag_for_selection(version, variant)
    with ui.working(f"Resolving {language.image_name}:{tag}…"):
        image_tag = provider.resolve(tag)

    vulns = report.lookup_digest(image_tag.digest)
    return ResolvedImage(
        language=language,
        tag=tag,
        digest=image_tag.digest,
        created=image_tag.last_updated,
        size=image_tag.size,
        vulnerabilities=vulns,
        cve_details=_critical_high_cves(vulns, image_tag.digest),
        version=version,
        variant=_display_variant(variant),
        is_lts=bool(_lts_versions(language, [version])),
        scan_source=ScanSource.from_report(report),
        report_source=report.source,
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
            "  image-inspector --dockerfile ./Dockerfile   # compare FROM images vs. latest\n"
            "  image-inspector --dockerfile ./Dockerfile --json   # machine-readable diff\n"
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
        help=(
            "non-interactive JSON output; with --language/--version for a single image, "
            "or with --dockerfile for the per-stage comparison"
        ),
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
    parser.add_argument(
        "--dockerfile",
        metavar="PATH",
        help="inspect a Dockerfile's FROM images: pinned digest vs. latest tracked digest",
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
        f"Multiple variants available; choose one with --variant. Options: {', '.join(variants)}"
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

    vulns = report.lookup_digest(image_tag.digest)
    image = ResolvedImage(
        language=language,
        tag=tag,
        digest=image_tag.digest,
        created=image_tag.last_updated,
        size=image_tag.size,
        vulnerabilities=vulns,
        cve_details=_critical_high_cves(vulns, image_tag.digest),
        version=version,
        variant=_display_variant(variant),
        is_lts=bool(_lts_versions(language, [version])),
        scan_source=ScanSource.from_report(report),
        report_source=report.source,
    )
    ui.show_result_json(image)
    return 0


def _run_dockerfile(args: argparse.Namespace) -> int:
    """Inspect a Dockerfile's ``FROM`` images and print the pinned-vs-latest comparison."""
    path = Path(args.dockerfile)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        ui.error(f"Could not read Dockerfile '{args.dockerfile}': {exc.strerror or exc}")
        return 2

    # Only load the report (and the lazy critical/high details sidecar, needed for the
    # fix-diff) once the Dockerfile is in hand, so an unreadable path never pays the cost
    # of fetching/decompressing the data.
    report = load_report()
    details = load_details()
    inspections = inspect_dockerfile(text, report, details)
    if args.json:
        ui.show_dockerfile_inspection_json(args.dockerfile, inspections, report)
    else:
        ui.render_dockerfile_inspection(inspections)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _build_parser().parse_args(argv)

    if args.dockerfile:
        ui.configure(plain=args.plain)
        return _run_dockerfile(args)

    report = load_report()

    if args.json:
        return _run_json(args, report)

    ui.configure(plain=args.plain)
    if not args.no_banner:
        ui.banner()

    # Tell the user when the bundled data is stale (newer online schema) or a newer tool
    # release is available. Offline-safe: the PyPI lookup is skipped/short-circuits offline.
    ui.show_version_status(report.source, report.generated_at, __version__, latest_pypi_version())

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
