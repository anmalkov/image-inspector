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
from collections.abc import Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from .models import LANGUAGES, LANGUAGES_BY_KEY, Language
from .registry import RegistryError, get_provider, make_client
from .report import SCHEMA_VERSION, _parse_dt
from .versions import select_versions, tag_for_selection, variants_for_version

MINOR_VERSION_COUNT = 5

# Retention policy applied when history is merged (see apply_retention). Keep a digest while it
# was the current digest of a tag within this window, capped per tag to bound report growth.
RETENTION_MAX_AGE_DAYS = 180
RETENTION_MAX_PER_TAG = 30

_DEFAULT_OUTPUT = Path(__file__).parent / "data" / "report.json"
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
# Generous timeout: CI fetches of the prior report / cached SBOMs should not hang a job.
_FETCH_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


@dataclass(frozen=True)
class ScanTarget:
    """One concrete image to scan, with its resolved digest."""

    reference: str  # e.g. "python:3.13.14-slim"
    image_ref: str  # e.g. "python@sha256:..." (what Trivy scans)
    digest: str


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _trivy_version_payload() -> dict:
    """Return the parsed ``trivy version --format json`` payload (``{}`` on error)."""
    try:
        proc = subprocess.run(
            ["trivy", "version", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return {}


def trivy_version() -> str | None:
    """Return the installed Trivy version, or ``None`` if it can't be read."""
    return _trivy_version_payload().get("Version")


def trivy_db_updated_at() -> str | None:
    """Return the vulnerability DB's ``UpdatedAt`` timestamp, or ``None``.

    Trivy also exposes ``VulnerabilityDB.Version``, but that is just an internal
    schema/build integer with no user-meaningful meaning, so we ignore it and
    surface only the DB's freshness date.
    """
    db = _trivy_version_payload().get("VulnerabilityDB") or {}
    return db.get("UpdatedAt") or None


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


def _sbom_name(digest: str) -> str:
    """Filesystem-safe SBOM filename for a digest (e.g. ``sha256-<hex>.cdx.json``)."""
    return digest.replace(":", "-") + ".cdx.json"


def generate_sbom(image_ref: str, out_path: Path) -> bool:
    """Generate a CycloneDX SBOM for ``image_ref`` (the one place that pulls the image).

    Returns ``True`` on success. SBOM generation analyses packages only, so it needs no
    vulnerability DB; scoring (``score_sbom``) applies the current DB later.
    """
    try:
        subprocess.run(
            [
                "trivy",
                "image",
                "--quiet",
                "--format",
                "cyclonedx",
                "--output",
                str(out_path),
                image_ref,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"  ! sbom generation failed for {image_ref}: {exc}", file=sys.stderr)
        return False


def score_sbom(sbom_path: Path) -> dict[str, int] | None:
    """Score a cached SBOM against the current Trivy DB (no image pull); counts or ``None``."""
    try:
        proc = subprocess.run(
            [
                "trivy",
                "sbom",
                "--quiet",
                "--format",
                "json",
                "--severity",
                ",".join(_SEVERITIES),
                str(sbom_path),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return parse_trivy_counts(json.loads(proc.stdout))
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"  ! trivy sbom failed for {sbom_path}: {exc}", file=sys.stderr)
        return None
    except json.JSONDecodeError as exc:
        print(f"  ! bad trivy sbom output for {sbom_path}: {exc}", file=sys.stderr)
        return None


class SbomStore:
    """Resolve a digest's SBOM, generating it at most once and re-using it forever.

    Lookup order for ``ensure``: local ``cache_dir`` → fetch ``<base_url>/sbom/<name>`` (the
    previously published copy on GitHub Pages) → ``generate_sbom`` (pull). The resolved SBOM is
    always copied into ``out_dir`` so the combine job can re-publish it. This keeps nightly
    pulls limited to digests that are new since the last run.
    """

    def __init__(self, cache_dir: Path, out_dir: Path, base_url: str | None = None) -> None:
        self.cache_dir = cache_dir
        self.out_dir = out_dir
        self.base_url = base_url.rstrip("/") if base_url else None
        cache_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

    def ensure(self, digest: str, image_ref: str) -> Path | None:
        """Return a local path to ``digest``'s SBOM, or ``None`` if it can't be obtained."""
        name = _sbom_name(digest)
        cached = self.cache_dir / name
        if (
            not cached.exists()
            and not self._fetch(name, cached)
            and not generate_sbom(image_ref, cached)
        ):
            return None
        self._publish(name, cached)
        return cached

    def _fetch(self, name: str, dest: Path) -> bool:
        if not self.base_url:
            return False
        try:
            resp = httpx.get(
                f"{self.base_url}/sbom/{name}", timeout=_FETCH_TIMEOUT, follow_redirects=True
            )
        except httpx.HTTPError:
            return False
        if resp.status_code != 200:
            return False
        try:
            dest.write_bytes(resp.content)
        except OSError:
            return False
        return True

    def _publish(self, name: str, src: Path) -> None:
        dest = self.out_dir / name
        if src.resolve() == dest.resolve():
            return
        with suppress(OSError):
            shutil.copyfile(src, dest)


def _score_target(target: ScanTarget, sbom_store: SbomStore | None) -> dict[str, int] | None:
    """Counts for a target: via the cached SBOM when available, else a direct image scan."""
    if sbom_store is None:
        return scan_image(target.image_ref)
    sbom = sbom_store.ensure(target.digest, target.image_ref)
    if sbom is None:
        return None
    return score_sbom(sbom)


def build_report(
    languages: tuple[Language, ...] = LANGUAGES,
    *,
    prior: dict | None = None,
    sbom_store: SbomStore | None = None,
) -> dict:
    """Scan the current images and return the full report payload.

    When ``prior`` is given, historical digests for ``languages`` (read from the prior report)
    are re-scored too, so a tag that moved keeps its old digest with up-to-date counts. A
    retained digest that can no longer be (re-)scored keeps its last-known counts. ``sbom_store``
    routes scoring through cached SBOMs so only digests new since the last run are pulled.
    """
    now = _utcnow_iso()
    images: dict[str, dict] = {}
    current: set[str] = set()
    for target in enumerate_targets(languages):
        current.add(target.digest)
        print(f"  scanning {target.reference} ({target.digest[:19]}…)", file=sys.stderr)
        counts = _score_target(target, sbom_store)
        if counts is None:
            continue
        images[target.digest] = {
            "reference": target.reference,
            **counts,
            "scanned_at": now,
            "last_active_at": now,
        }

    if prior is not None:
        prior_images = prior.get("images") or {}
        for target in retained_targets(prior, languages, exclude=current):
            entry = prior_images.get(target.digest)
            print(f"  re-scoring {target.reference} ({target.digest[:19]}…)", file=sys.stderr)
            counts = _score_target(target, sbom_store)
            if counts is None:
                # Carry the last-known counts forward (e.g. the image was GC'd from the registry).
                if isinstance(entry, dict):
                    images[target.digest] = dict(entry)
                continue
            images[target.digest] = {
                "reference": target.reference,
                **counts,
                "scanned_at": now,
                "last_active_at": _last_active_value(entry, fallback=now),
            }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "trivy_version": trivy_version(),
        "trivy_db_updated_at": trivy_db_updated_at(),
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
    parser.add_argument(
        "--prior-url",
        help="URL of the previously published report.json; its history is re-scored and merged.",
    )
    parser.add_argument(
        "--sbom-cache-dir",
        type=Path,
        help="Directory of cached SBOMs to reuse (defaults to --sbom-out-dir when omitted).",
    )
    parser.add_argument(
        "--sbom-out-dir",
        type=Path,
        help="Directory to write the SBOMs used this run (enables SBOM-based scoring).",
    )
    parser.add_argument(
        "--sbom-base-url",
        help="Base URL to fetch previously published SBOMs from (e.g. the Pages site root).",
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

    build_kwargs: dict = {}
    if args.prior_url:
        build_kwargs["prior"] = fetch_prior_report(args.prior_url)
    if args.sbom_out_dir is not None:
        cache_dir = args.sbom_cache_dir or args.sbom_out_dir
        build_kwargs["sbom_store"] = SbomStore(
            cache_dir, args.sbom_out_dir, base_url=args.sbom_base_url
        )

    report = build_report(selected, **build_kwargs)
    _write_report(report, args.output)
    return 0


def merge_reports(payloads: list[dict]) -> dict:
    """Combine several per-language reports into one (union of images by digest)."""
    images: dict[str, dict] = {}
    trivy: str | None = None
    db_updated: str | None = None
    generated: list[str] = []
    for payload in payloads:
        images.update(payload.get("images") or {})
        trivy = trivy or payload.get("trivy_version")
        db_updated = db_updated or payload.get("trivy_db_updated_at")
        if payload.get("generated_at"):
            generated.append(payload["generated_at"])
    return {
        "schema_version": SCHEMA_VERSION,
        # ISO-8601 UTC strings sort lexicographically, so max() is the latest.
        "generated_at": max(generated) if generated else _utcnow_iso(),
        "trivy_version": trivy,
        "trivy_db_updated_at": db_updated,
        "images": images,
    }


def fetch_prior_report(url: str) -> dict | None:
    """Fetch + light-validate the previously published report; ``None`` on any failure.

    Used to seed history from the GitHub Pages copy. A missing/404/malformed prior is treated as
    empty history so the nightly never fails on a cold start or a transient Pages error.
    """
    try:
        resp = httpx.get(url, timeout=_FETCH_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("images"), dict):
        return None
    return data


def retained_targets(
    prior: dict, languages: tuple[Language, ...], *, exclude: set[str]
) -> Iterator[ScanTarget]:
    """Yield prior digests belonging to ``languages`` that are not currently enumerated.

    A retained digest's image reference is reconstructed from its ``reference`` (``name:tag``):
    the name before the last ``:`` plus ``@<digest>``.
    """
    names = {lang.image_name for lang in languages}
    for digest, entry in (prior.get("images") or {}).items():
        if digest in exclude or not isinstance(entry, dict):
            continue
        reference = entry.get("reference")
        if not isinstance(reference, str) or ":" not in reference:
            continue
        name = reference.rsplit(":", 1)[0]
        if name not in names:
            continue
        yield ScanTarget(reference=reference, image_ref=f"{name}@{digest}", digest=digest)


def _entry_dt(entry: dict, field: str) -> datetime | None:
    value = entry.get(field)
    dt = _parse_dt(value) if isinstance(value, str) else None
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _last_active(entry: dict) -> datetime | None:
    """When the digest was last a live tag; falls back to ``scanned_at`` for older entries."""
    return _entry_dt(entry, "last_active_at") or _entry_dt(entry, "scanned_at")


def _last_active_value(entry: dict | None, *, fallback: str) -> str:
    if isinstance(entry, dict):
        for field in ("last_active_at", "scanned_at"):
            value = entry.get(field)
            if isinstance(value, str) and value:
                return value
    return fallback


def _retention_sort_key(item: tuple[str, dict]) -> tuple[bool, datetime, str]:
    active = _last_active(item[1]) if isinstance(item[1], dict) else None
    return (active is not None, active or datetime.min.replace(tzinfo=UTC), item[0])


def apply_retention(
    images: dict[str, dict],
    *,
    now: datetime | None = None,
    max_age_days: int = RETENTION_MAX_AGE_DAYS,
    max_per_tag: int = RETENTION_MAX_PER_TAG,
) -> dict[str, dict]:
    """Trim history deterministically: drop stale digests and cap each tag.

    Grouped by ``reference`` (a moved tag keeps the same ``name:tag``), entries whose
    ``last_active_at`` is older than ``max_age_days`` are dropped, then each tag keeps only its
    ``max_per_tag`` most-recently-active digests. Undated entries are never aged out but sort
    last and still count toward the cap.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=max_age_days)
    groups: dict[str, list[tuple[str, dict]]] = {}
    for digest, entry in images.items():
        ref = entry.get("reference") if isinstance(entry, dict) else None
        groups.setdefault(ref if isinstance(ref, str) else "", []).append((digest, entry))

    kept: dict[str, dict] = {}
    for items in groups.values():
        items.sort(key=_retention_sort_key, reverse=True)
        count = 0
        for digest, entry in items:
            active = _last_active(entry) if isinstance(entry, dict) else None
            if active is not None and active < cutoff:
                continue
            if count >= max_per_tag:
                break
            kept[digest] = entry
            count += 1
    return kept


def merge_with_history(fresh: dict, prior: dict | None, *, now: datetime | None = None) -> dict:
    """Merge this run's ``fresh`` images over the ``prior`` report, then apply retention.

    Fresh entries win per digest (so re-scored active tags refresh while old digests survive);
    header fields come from ``fresh`` so freshness metadata is never stale.
    """
    images: dict[str, dict] = {}
    if prior:
        images.update(prior.get("images") or {})
    images.update(fresh.get("images") or {})
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": fresh.get("generated_at") or _utcnow_iso(),
        "trivy_version": fresh.get("trivy_version"),
        "trivy_db_updated_at": fresh.get("trivy_db_updated_at"),
        "images": apply_retention(images, now=now),
    }


def _write_report(report: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(report['images'])} image(s) to {output}", file=sys.stderr)


def publish_sboms(digests: Iterable[str], src_dir: Path, out_dir: Path) -> int:
    """Copy each digest's SBOM from ``src_dir`` into ``out_dir`` (skipping any that are missing).

    Used by the combine job to publish only the SBOMs for digests retained in the final report,
    so the Pages ``sbom/`` directory stays bounded by the retention policy. Returns the count
    copied.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for digest in digests:
        src = src_dir / _sbom_name(digest)
        if not src.exists():
            continue
        try:
            shutil.copyfile(src, out_dir / src.name)
        except OSError:
            continue
        copied += 1
    return copied


def merge_main(argv: list[str] | None = None) -> int:
    """Entry point for ``image-inspector-merge``: combine per-language reports."""
    parser = argparse.ArgumentParser(
        description="Merge per-language scan reports (e.g. from a CI matrix) into one report.",
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Report JSON files to merge.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help="Where to write the combined report (default: packaged data/report.json).",
    )
    parser.add_argument(
        "--prior-url",
        help="URL of the previously published report.json to merge history from (optional).",
    )
    parser.add_argument(
        "--sbom-src-dir",
        type=Path,
        help="Directory of this run's SBOMs; with --sbom-out-dir, publish retained ones.",
    )
    parser.add_argument(
        "--sbom-out-dir",
        type=Path,
        help="Directory to copy retained digests' SBOMs into (requires --sbom-src-dir).",
    )
    args = parser.parse_args(argv)

    payloads: list[dict] = []
    for path in args.inputs:
        try:
            payloads.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read report {path}: {exc}", file=sys.stderr)
            return 1

    fresh = merge_reports(payloads)
    prior = fetch_prior_report(args.prior_url) if args.prior_url else None
    combined = merge_with_history(fresh, prior)
    _write_report(combined, args.output)
    if args.sbom_src_dir is not None and args.sbom_out_dir is not None:
        copied = publish_sboms(combined["images"], args.sbom_src_dir, args.sbom_out_dir)
        print(f"Published {copied} SBOM(s) to {args.sbom_out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
