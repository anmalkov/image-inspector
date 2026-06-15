"""Nightly scanner: enumerate every selectable image and scan it with Trivy.

Run via the ``image-inspector-scan`` console script (typically in CI). It reuses
the same enumeration and digest-resolution logic as the interactive picker, so
the produced ``report.json`` is keyed by exactly the digests the inspector will
look up. Trivy is required at runtime here (a CI-only dependency), not for the
interactive tool.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import LANGUAGES, LANGUAGES_BY_KEY, Language
from .registry import RegistryError, get_provider, make_client
from .report import SCHEMA_VERSION
from .versions import select_versions, tag_for_selection, variants_for_version

MINOR_VERSION_COUNT = 5

_DEFAULT_OUTPUT = Path(__file__).parent / "data" / "report.json"
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


@dataclass(frozen=True)
class ScanTarget:
    """One concrete image to scan, with its resolved digest."""

    reference: str  # e.g. "python:3.13.14-slim"
    image_ref: str  # e.g. "python@sha256:..." (what Trivy scans)
    digest: str


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def trivy_version() -> str | None:
    """Return the installed Trivy version, or ``None`` if it can't be read."""
    try:
        proc = subprocess.run(
            ["trivy", "version", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout).get("Version")
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def enumerate_targets(languages: tuple[Language, ...] = LANGUAGES) -> Iterator[ScanTarget]:
    """Yield every selectable image (all versions, all variants) with its digest.

    Uses the same registry providers as the interactive flow, so each digest
    matches what the picker resolves for the corresponding tag.
    """
    with make_client() as client:
        for language in languages:
            try:
                provider = get_provider(language, client)
                tag_names = provider.list_tag_names(want_minors=MINOR_VERSION_COUNT)
                versions = select_versions(tag_names, language.scheme, count=MINOR_VERSION_COUNT)
                for version in versions:
                    for variant in variants_for_version(tag_names, version):
                        tag = tag_for_selection(version, variant)
                        image_tag = provider.resolve(tag)
                        yield ScanTarget(
                            reference=f"{language.image_name}:{tag}",
                            image_ref=f"{language.image_name}@{image_tag.digest}",
                            digest=image_tag.digest,
                        )
            except RegistryError as exc:
                print(f"  ! skipping {language.label}: {exc}", file=sys.stderr)


def _empty_counts() -> dict[str, int]:
    return {sev.lower(): 0 for sev in _SEVERITIES}


def parse_trivy_counts(payload: dict) -> dict[str, int]:
    """Count vulnerabilities by severity from Trivy JSON output."""
    counts = _empty_counts()
    for result in payload.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity", "UNKNOWN")).lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["unknown"] += 1
    counts["total"] = sum(counts[sev.lower()] for sev in _SEVERITIES)
    return counts


def scan_image(image_ref: str) -> dict[str, int] | None:
    """Run Trivy on ``image_ref`` and return severity counts, or ``None`` on error."""
    try:
        proc = subprocess.run(
            [
                "trivy",
                "image",
                "--quiet",
                "--format",
                "json",
                "--severity",
                ",".join(_SEVERITIES),
                image_ref,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return parse_trivy_counts(json.loads(proc.stdout))
    except subprocess.CalledProcessError as exc:
        print(f"  ! trivy failed for {image_ref}: {exc.stderr.strip()}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"  ! bad trivy output for {image_ref}: {exc}", file=sys.stderr)
        return None


def build_report(languages: tuple[Language, ...] = LANGUAGES) -> dict:
    """Scan all images and return the full report payload."""
    images: dict[str, dict] = {}
    for target in enumerate_targets(languages):
        print(f"  scanning {target.reference} ({target.digest[:19]}…)", file=sys.stderr)
        counts = scan_image(target.image_ref)
        if counts is None:
            continue
        images[target.digest] = {
            "reference": target.reference,
            **counts,
            "scanned_at": _utcnow_iso(),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utcnow_iso(),
        "trivy_version": trivy_version(),
        "images": images,
    }


def _update_db() -> None:
    """Pre-download the Trivy vulnerability DB so per-image scans are faster."""
    with suppress(OSError, subprocess.CalledProcessError):
        subprocess.run(
            ["trivy", "image", "--download-db-only"],
            capture_output=True,
            text=True,
            check=True,
        )


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``image-inspector-scan`` console script."""
    parser = argparse.ArgumentParser(description="Scan all selectable images with Trivy.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help="Where to write the JSON report (default: packaged data/report.json).",
    )
    parser.add_argument(
        "-l",
        "--language",
        action="append",
        dest="languages",
        metavar="KEY",
        choices=[lang.key for lang in LANGUAGES],
        help=(
            "Only scan this language/image (repeatable, e.g. -l python -l alpine). "
            "Choices: " + ", ".join(lang.key for lang in LANGUAGES) + ". Default: all."
        ),
    )
    parser.add_argument(
        "--skip-db-update",
        action="store_true",
        help="Do not pre-download the Trivy vulnerability database.",
    )
    args = parser.parse_args(argv)

    if shutil.which("trivy") is None:
        print("error: trivy is not installed or not on PATH.", file=sys.stderr)
        return 1

    if args.languages:
        # Preserve order, drop duplicates.
        selected = tuple(dict.fromkeys(LANGUAGES_BY_KEY[key] for key in args.languages))
    else:
        selected = LANGUAGES

    if not args.skip_db_update:
        _update_db()

    report = build_report(selected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"Wrote {len(report['images'])} image(s) to {args.output}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
