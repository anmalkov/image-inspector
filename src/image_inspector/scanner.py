"""Nightly scanner: enumerate every selectable image and scan it with Trivy.

Run via the ``image-inspector-scan`` console script (typically in CI). It reuses
the same enumeration and digest-resolution logic as the interactive picker, so
the produced report's history is keyed by exactly the digests the inspector will
look up. Trivy is required at runtime here (a CI-only dependency), not for the
interactive tool.
"""

from __future__ import annotations

import argparse
import gzip
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
from .report import SCHEMA_VERSION, _decode_report_bytes, _parse_dt, _strip_digest
from .versions import select_versions, tag_for_selection, variants_for_version

MINOR_VERSION_COUNT = 5

# Retention policy applied when history is merged (see apply_retention). Keep a digest while it
# was the current digest of a tag within this window, capped per tag to bound report growth.
RETENTION_MAX_AGE_DAYS = 180
RETENTION_MAX_PER_TAG = 30

_DEFAULT_OUTPUT = Path(__file__).parent / "data" / "report.json.gz"
_DEFAULT_DETAILS_OUTPUT = Path(__file__).parent / "data" / "details.json.gz"
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
# Details sidecar stores critical+high only, mapped to single-letter codes.
_DETAIL_SEVERITIES = {"CRITICAL": "C", "HIGH": "H"}
# Generous timeout: CI fetches of the prior report / cached SBOMs should not hang a job.
_FETCH_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


@dataclass(frozen=True)
class ScanTarget:
    """One concrete image to scan, with its resolved digest.

    ``created`` is the image's created-at timestamp (ISO-8601 string, or ``None`` when the
    registry/prior report doesn't provide one). It is captured once and stored as the v3
    history entry's ``t`` so a digest's age survives later re-scores.
    """

    reference: str  # e.g. "python:3.13.14-slim"
    image_ref: str  # e.g. "python@sha256:..." (what Trivy scans)
    digest: str
    created: str | None = None


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
                            created=_iso(image_tag.last_updated),
                        )
            except RegistryError as exc:
                print(f"  ! skipping {language.label}: {exc}", file=sys.stderr)


def _iso(dt: datetime | None) -> str | None:
    """Format a datetime as a ``YYYY-MM-DDTHH:MM:SSZ`` UTC string (``None`` passes through)."""
    if dt is None:
        return None
    aware = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
    return aware.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0


def _counts_to_c(counts: dict) -> list[int]:
    """Pack a severity-counts dict into the compact ``c`` array order."""
    return [_int(counts.get(sev.lower(), 0)) for sev in _SEVERITIES]


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


def parse_trivy_details(payload: dict) -> list[dict]:
    """Extract deduped critical+high CVE detail records from Trivy JSON output.

    Each record is trimmed to ``{id, pkg, sev, fix}`` where ``sev`` is ``C``/``H`` and
    ``fix`` is the fixed version (or ``None`` when there is no fix yet). Medium/low/unknown
    are intentionally dropped — the fix-diff is critical+high only. Records are deduped on
    all four fields so a digest's index list never points at duplicate CVE/pkg pairs.
    """
    seen: set[tuple[str, str, str, str | None]] = set()
    records: list[dict] = []
    for result in payload.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            sev = _DETAIL_SEVERITIES.get(str(vuln.get("Severity", "")).upper())
            if sev is None:
                continue
            cve_id = vuln.get("VulnerabilityID")
            if not isinstance(cve_id, str) or not cve_id:
                continue
            pkg = vuln.get("PkgName")
            fixed = vuln.get("FixedVersion")
            pkg = pkg if isinstance(pkg, str) else ""
            fix = fixed if isinstance(fixed, str) and fixed else None
            key = (cve_id, pkg, sev, fix)
            if key in seen:
                continue
            seen.add(key)
            records.append({"id": cve_id, "pkg": pkg, "sev": sev, "fix": fix})
    return records


def scan_image(image_ref: str) -> dict[str, int] | None:
    """Run Trivy on ``image_ref`` and return severity counts, or ``None`` on error."""
    payload = _scan_image_payload(image_ref)
    return None if payload is None else parse_trivy_counts(payload)


def scan_image_full(image_ref: str) -> tuple[dict[str, int], list[dict]] | None:
    """Scan ``image_ref`` once, returning ``(counts, C/H details)`` or ``None`` on error."""
    payload = _scan_image_payload(image_ref)
    if payload is None:
        return None
    return parse_trivy_counts(payload), parse_trivy_details(payload)


def _scan_image_payload(image_ref: str) -> dict | None:
    """Run Trivy on ``image_ref`` and return the parsed JSON payload, or ``None`` on error."""
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
        return json.loads(proc.stdout)
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
    except subprocess.CalledProcessError as exc:
        print(f"  ! sbom generation failed for {image_ref}: {exc.stderr.strip()}", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"  ! sbom generation failed for {image_ref}: {exc}", file=sys.stderr)
        return False


def score_sbom(sbom_path: Path) -> dict[str, int] | None:
    """Score a cached SBOM against the current Trivy DB (no image pull); counts or ``None``."""
    payload = _score_sbom_payload(sbom_path)
    return None if payload is None else parse_trivy_counts(payload)


def score_sbom_full(sbom_path: Path) -> tuple[dict[str, int], list[dict]] | None:
    """Score a cached SBOM, returning ``(counts, C/H details)`` or ``None`` on error."""
    payload = _score_sbom_payload(sbom_path)
    if payload is None:
        return None
    return parse_trivy_counts(payload), parse_trivy_details(payload)


def _score_sbom_payload(sbom_path: Path) -> dict | None:
    """Score a cached SBOM and return the parsed JSON payload, or ``None`` on error."""
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
        return json.loads(proc.stdout)
    except subprocess.CalledProcessError as exc:
        print(f"  ! trivy sbom failed for {sbom_path}: {exc.stderr.strip()}", file=sys.stderr)
        return None
    except OSError as exc:
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


def _score_target_full(
    target: ScanTarget, sbom_store: SbomStore | None
) -> tuple[dict[str, int], list[dict]] | None:
    """Counts + C/H details for a target (cached SBOM when available, else image scan)."""
    if sbom_store is None:
        return scan_image_full(target.image_ref)
    sbom = sbom_store.ensure(target.digest, target.image_ref)
    if sbom is None:
        return None
    return score_sbom_full(sbom)


def build_report(
    languages: tuple[Language, ...] = LANGUAGES,
    *,
    prior: dict | None = None,
    sbom_store: SbomStore | None = None,
    details_out: dict[str, list[dict]] | None = None,
    prior_details: dict | None = None,
) -> dict:
    """Scan the current images and return the full v3 report payload.

    When ``prior`` is given, historical digests for ``languages`` (read from the prior report)
    are re-scored too, so a tag that moved keeps its old digest with up-to-date counts. A
    retained digest that can no longer be (re-)scored keeps its last-known entry. ``sbom_store``
    routes scoring through cached SBOMs so only digests new since the last run are pulled.

    Each tag's ``history`` holds ``{d, t, c}`` entries newest-``t``-first: ``d`` is the digest
    without the ``sha256:`` prefix, ``t`` the image created-at, ``c`` the severity counts.

    When ``details_out`` is provided, the deduped critical+high CVE records for each scanned
    digest are collected into it (stripped digest -> list of ``{id, pkg, sev, fix}``) so the
    caller can write the lazy details sidecar; ``prior_details`` lets a failed re-score carry a
    digest's known C/H records forward. Without ``details_out`` the cheaper counts-only path
    runs unchanged.
    """
    now = _utcnow_iso()
    # reference -> list of {d, t, c} entries (fresh wins per digest).
    tags: dict[str, list[dict]] = {}
    current: set[str] = set()
    for target in enumerate_targets(languages):
        current.add(target.digest)
        print(f"  scanning {target.reference} ({target.digest[:19]}…)", file=sys.stderr)
        counts = _score_one(target, sbom_store, details_out)
        if counts is None:
            continue
        _set_entry(tags, target.reference, _make_entry(target.digest, target.created, counts))

    if prior is not None:
        prior_tags = _prior_tags(prior)
        for target in retained_targets(prior, languages, exclude=current):
            print(f"  re-scoring {target.reference} ({target.digest[:19]}…)", file=sys.stderr)
            counts = _score_one(target, sbom_store, details_out)
            if counts is None:
                # Carry the last-known entry forward (e.g. the image was GC'd from the registry).
                entry = _prior_entry(prior_tags, target.reference, target.digest)
                if entry is not None:
                    _set_entry(tags, target.reference, dict(entry))
                _carry_details(details_out, prior_details, target.digest)
                continue
            _set_entry(tags, target.reference, _make_entry(target.digest, target.created, counts))

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "trivy_version": trivy_version(),
        "trivy_db_updated_at": trivy_db_updated_at(),
        "tags": _finalize_tags(tags),
    }


def _make_entry(digest: str, created: str | None, counts: dict) -> dict:
    """Build a compact ``{d, t, c}`` history entry."""
    return {"d": _strip_digest(digest), "t": created, "c": _counts_to_c(counts)}


def _score_one(
    target: ScanTarget,
    sbom_store: SbomStore | None,
    details_out: dict[str, list[dict]] | None,
) -> dict[str, int] | None:
    """Score one target, recording its C/H details into ``details_out`` when requested."""
    if details_out is None:
        return _score_target(target, sbom_store)
    scored = _score_target_full(target, sbom_store)
    if scored is None:
        return None
    counts, details = scored
    details_out[_strip_digest(target.digest)] = details
    return counts


def _carry_details(
    details_out: dict[str, list[dict]] | None,
    prior_details: dict | None,
    digest: str,
) -> None:
    """Carry a digest's prior C/H records forward when a re-score fails (best-effort)."""
    if details_out is None:
        return
    records = _prior_digest_records(prior_details, digest)
    if records:
        details_out[_strip_digest(digest)] = records


def _set_entry(tags: dict[str, list[dict]], reference: str, entry: dict) -> None:
    """Insert ``entry`` into ``reference``'s history, replacing any same-digest entry."""
    history = tags.setdefault(reference, [])
    for index, existing in enumerate(history):
        if existing.get("d") == entry["d"]:
            history[index] = entry
            return
    history.append(entry)


def _prior_entry(tags: dict[str, list[dict]], reference: str, digest: str) -> dict | None:
    """Return the stored history entry for ``reference``/``digest`` (``None`` if absent)."""
    stripped = _strip_digest(digest)
    for entry in tags.get(reference, []):
        if entry.get("d") == stripped:
            return entry
    return None


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
        help="Where to write the report (default: packaged data/report.json.gz; "
        "a .gz path is gzipped, otherwise plain JSON).",
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
        help="URL of the previously published report; its history is re-scored and merged.",
    )
    parser.add_argument(
        "--details-output",
        type=Path,
        default=_DEFAULT_DETAILS_OUTPUT,
        help="Where to write the critical+high CVE details sidecar (default: packaged "
        "data/details.json.gz; a .gz path is gzipped, otherwise plain JSON).",
    )
    parser.add_argument(
        "--details-prior-url",
        help="URL of the previously published details sidecar; carried forward when a "
        "retained digest can no longer be re-scored.",
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

    details_out: dict[str, list[dict]] = {}
    build_kwargs["details_out"] = details_out
    if args.details_prior_url:
        build_kwargs["prior_details"] = fetch_prior_details(args.details_prior_url)

    report = build_report(selected, **build_kwargs)
    _write_report(report, args.output)
    sidecar = build_details_sidecar(details_out, keep_digests=_retained_digests(report))
    _write_report(sidecar, args.details_output)
    return 0


def merge_reports(payloads: list[dict]) -> dict:
    """Combine several per-language reports into one (union of tags, merged histories)."""
    tags: dict[str, list[dict]] = {}
    trivy: str | None = None
    db_updated: str | None = None
    generated: list[str] = []
    for payload in payloads:
        for reference, history in _prior_tags(payload).items():
            bucket = tags.setdefault(reference, [])
            seen = {entry["d"] for entry in bucket}
            for entry in history:
                if entry["d"] not in seen:
                    bucket.append(entry)
                    seen.add(entry["d"])
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
        "tags": _finalize_tags(tags),
    }


def fetch_prior_report(url: str) -> dict | None:
    """Fetch + light-validate the previously published report; ``None`` on any failure.

    Used to seed history from the GitHub Pages copy. The body is gunzipped when gzipped, else
    read as UTF-8 JSON. A v3 (``tags``) or legacy v2 (``images``) payload is accepted so a
    cutover keeps prior history; a missing/404/malformed prior is treated as empty history so
    the nightly never fails on a cold start or a transient Pages error.
    """
    try:
        resp = httpx.get(url, timeout=_FETCH_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    body = _decode_report_bytes(resp.content)
    if body is None:
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("tags"), dict) or isinstance(data.get("images"), dict):
        return data
    return None


def retained_targets(
    prior: dict, languages: tuple[Language, ...], *, exclude: set[str]
) -> Iterator[ScanTarget]:
    """Yield prior digests belonging to ``languages`` that are not currently enumerated.

    Reads the prior report's tag histories (migrating a legacy v2 payload if needed) and
    reconstructs each retained digest's full ``sha256:`` reference and stored created-at so
    re-scoring preserves its ``t``.
    """
    names = {lang.image_name for lang in languages}
    for reference, history in _prior_tags(prior).items():
        if ":" not in reference:
            continue
        name = reference.rsplit(":", 1)[0]
        if name not in names:
            continue
        for entry in history:
            digest = entry.get("d")
            if not isinstance(digest, str) or not digest:
                continue
            full = digest if digest.startswith("sha256:") else f"sha256:{digest}"
            if full in exclude:
                continue
            created = entry.get("t")
            yield ScanTarget(
                reference=reference,
                image_ref=f"{name}@{full}",
                digest=full,
                created=created if isinstance(created, str) else None,
            )


def _entry_dt(entry: dict) -> datetime | None:
    """Parse a history entry's created-at (``t``) as an aware UTC datetime, or ``None``."""
    value = entry.get("t")
    dt = _parse_dt(value) if isinstance(value, str) else None
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _entry_sort_key(entry: dict) -> tuple[bool, datetime, str]:
    """Sort key for newest-``t``-first ordering; undated entries sort last (with reverse).

    The ``d`` tiebreaker keeps ordering deterministic when two entries share a ``t``.
    """
    dt = _entry_dt(entry)
    return (dt is not None, dt or datetime.min.replace(tzinfo=UTC), str(entry.get("d") or ""))


def _normalize_v3_tags(tags: dict) -> dict[str, list[dict]]:
    """Coerce a v3 ``tags`` payload into ``{reference: [clean {d, t, c}, ...]}``."""
    result: dict[str, list[dict]] = {}
    for reference, tag_data in tags.items():
        if not isinstance(reference, str):
            continue
        history = tag_data.get("history") if isinstance(tag_data, dict) else None
        if not isinstance(history, list):
            continue
        cleaned = [e for e in (_clean_entry(entry) for entry in history) if e is not None]
        if cleaned:
            result[reference] = cleaned
    return result


def _clean_entry(entry: object) -> dict | None:
    """Validate/normalise one history entry to ``{d, t, c}`` (``None`` if unusable)."""
    if not isinstance(entry, dict):
        return None
    digest = entry.get("d")
    if not isinstance(digest, str) or not digest:
        return None
    counts = entry.get("c")
    c = [_int(x) for x in counts[:5]] if isinstance(counts, list) else []
    c += [0] * (5 - len(c))
    t = entry.get("t")
    return {"d": _strip_digest(digest), "t": t if isinstance(t, str) else None, "c": c}


def _migrate_v2_images(images: dict) -> dict[str, list[dict]]:
    """Migrate a legacy v2 ``images`` map to v3 ``{reference: [{d, t, c}, ...]}``.

    ``t`` is taken best-effort from the old ``last_active_at``/``scanned_at`` fields and ``c``
    from the old per-severity counts, so accumulated history survives the cutover.
    """
    result: dict[str, list[dict]] = {}
    for digest, entry in images.items():
        if not isinstance(digest, str) or not isinstance(entry, dict):
            continue
        reference = entry.get("reference")
        if not isinstance(reference, str) or ":" not in reference:
            continue
        c = [_int(entry.get(sev.lower(), 0)) for sev in _SEVERITIES]
        t = entry.get("last_active_at") or entry.get("scanned_at")
        result.setdefault(reference, []).append(
            {"d": _strip_digest(digest), "t": t if isinstance(t, str) else None, "c": c}
        )
    return result


def _prior_tags(prior: dict | None) -> dict[str, list[dict]]:
    """Return a normalised ``{reference: [{d, t, c}, ...]}`` view of any report payload.

    Accepts a v3 ``tags`` payload or a legacy v2 ``images`` payload (migrated on the fly);
    anything else yields an empty mapping.
    """
    if not isinstance(prior, dict):
        return {}
    tags = prior.get("tags")
    if isinstance(tags, dict):
        return _normalize_v3_tags(tags)
    images = prior.get("images")
    if isinstance(images, dict):
        return _migrate_v2_images(images)
    return {}


def _finalize_tags(tags: dict[str, list[dict]]) -> dict[str, dict]:
    """Wrap each reference's entries into ``{"history": [...]}``, newest-``t``-first."""
    result: dict[str, dict] = {}
    for reference, history in tags.items():
        ordered = sorted(history, key=_entry_sort_key, reverse=True)
        result[reference] = {"history": ordered}
    return result


def apply_retention(
    tags: dict[str, dict],
    *,
    now: datetime | None = None,
    max_age_days: int = RETENTION_MAX_AGE_DAYS,
    max_per_tag: int = RETENTION_MAX_PER_TAG,
) -> dict[str, dict]:
    """Trim each tag's history deterministically: drop stale digests and cap depth.

    With history ordered newest-``t``-first, entry ``i``'s successor ``history[i-1]`` is the
    image that replaced it, so ``history[i-1].t`` is when entry ``i`` was retired. A non-head
    entry is dropped when that supersession time is older than ``max_age_days``; the head is
    the live digest and is never aged out. Each tag then keeps at most ``max_per_tag`` newest
    entries. Undated ``t`` never ages out, sorts last, and still counts toward the cap.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=max_age_days)
    result: dict[str, dict] = {}
    for reference, tag_data in tags.items():
        history = tag_data.get("history") if isinstance(tag_data, dict) else None
        if not isinstance(history, list):
            continue
        ordered = sorted(
            (e for e in history if isinstance(e, dict)), key=_entry_sort_key, reverse=True
        )
        kept: list[dict] = []
        for index, entry in enumerate(ordered):
            if index > 0:
                superseded_at = _entry_dt(ordered[index - 1])
                if superseded_at is not None and superseded_at < cutoff:
                    continue
            kept.append(entry)
            if len(kept) >= max_per_tag:
                break
        if kept:
            result[reference] = {"history": kept}
    return result


def merge_with_history(fresh: dict, prior: dict | None, *, now: datetime | None = None) -> dict:
    """Merge this run's ``fresh`` tags over the ``prior`` report, then apply retention.

    Fresh entries win per digest (so re-scored active tags refresh while old digests survive);
    header fields come from ``fresh`` so freshness metadata is never stale.
    """
    merged: dict[str, list[dict]] = {
        reference: [dict(entry) for entry in history]
        for reference, history in _prior_tags(prior).items()
    }
    for reference, history in _prior_tags(fresh).items():
        bucket = merged.setdefault(reference, [])
        index_by_digest = {entry["d"]: i for i, entry in enumerate(bucket)}
        for entry in history:
            position = index_by_digest.get(entry["d"])
            if position is None:
                index_by_digest[entry["d"]] = len(bucket)
                bucket.append(entry)
            else:
                bucket[position] = entry
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": fresh.get("generated_at") or _utcnow_iso(),
        "trivy_version": fresh.get("trivy_version"),
        "trivy_db_updated_at": fresh.get("trivy_db_updated_at"),
        "tags": apply_retention(_finalize_tags(merged), now=now),
    }


DETAILS_SCHEMA_VERSION = SCHEMA_VERSION


def _detail_key(record: dict) -> tuple[str, str, str, str | None]:
    """Identity of a C/H detail record for dedup: ``(id, pkg, sev, fix)``."""
    fix = record.get("fix")
    return (
        str(record.get("id") or ""),
        str(record.get("pkg") or ""),
        str(record.get("sev") or ""),
        fix if isinstance(fix, str) and fix else None,
    )


def build_details_sidecar(
    details: dict[str, list[dict]], *, keep_digests: set[str] | None = None
) -> dict:
    """Pack a ``{digest: [C/H records]}`` map into the deduped sidecar payload.

    Produces ``{schema_version, vulns, digests}``: ``vulns`` is the deduped C/H record table
    and ``digests`` maps each stripped digest to sorted integer indices into ``vulns``. When
    ``keep_digests`` is given (stripped digests), only those digests are kept so the table
    stays bounded by the report's retention; CVE records no longer referenced are dropped.
    """
    vulns: list[dict] = []
    index_by_key: dict[tuple[str, str, str, str | None], int] = {}
    digests: dict[str, list[int]] = {}
    for digest, records in details.items():
        stripped = _strip_digest(digest)
        if keep_digests is not None and stripped not in keep_digests:
            continue
        indices: set[int] = set()
        for record in records:
            if not isinstance(record, dict) or not record.get("id"):
                continue
            key = _detail_key(record)
            position = index_by_key.get(key)
            if position is None:
                position = len(vulns)
                index_by_key[key] = position
                vulns.append({"id": key[0], "pkg": key[1], "sev": key[2], "fix": key[3]})
            indices.add(position)
        if indices:
            digests[stripped] = sorted(indices)
    return {"schema_version": DETAILS_SCHEMA_VERSION, "vulns": vulns, "digests": digests}


def details_from_sidecar(payload: dict | None) -> dict[str, list[dict]]:
    """Reconstruct a ``{digest: [C/H records]}`` map from a sidecar payload (best-effort).

    Out-of-range indices and malformed entries are skipped so a corrupt sidecar degrades to
    partial/empty details rather than raising.
    """
    if not isinstance(payload, dict):
        return {}
    vulns = payload.get("vulns")
    digests = payload.get("digests")
    if not isinstance(vulns, list) or not isinstance(digests, dict):
        return {}
    result: dict[str, list[dict]] = {}
    for digest, indices in digests.items():
        if not isinstance(digest, str) or not isinstance(indices, list):
            continue
        records: list[dict] = []
        for i in indices:
            if isinstance(i, int) and 0 <= i < len(vulns) and isinstance(vulns[i], dict):
                records.append(vulns[i])
        if records:
            result[_strip_digest(digest)] = records
    return result


def _prior_digest_records(prior_details: dict | None, digest: str) -> list[dict]:
    """Return one digest's C/H records from a prior sidecar payload (empty if absent)."""
    return details_from_sidecar(prior_details).get(_strip_digest(digest), [])


def merge_details(maps: Iterable[dict[str, list[dict]]]) -> dict[str, list[dict]]:
    """Union per-digest detail maps; first writer wins for a digest already present."""
    merged: dict[str, list[dict]] = {}
    for details in maps:
        for digest, records in details.items():
            merged.setdefault(_strip_digest(digest), records)
    return merged


def fetch_prior_details(url: str) -> dict | None:
    """Fetch + light-validate the previously published details sidecar; ``None`` on failure."""
    try:
        resp = httpx.get(url, timeout=_FETCH_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    body = _decode_report_bytes(resp.content)
    if body is None:
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and isinstance(data.get("vulns"), list):
        return data
    return None


def _retained_digests(report: dict) -> set[str]:
    """Stripped digests retained in ``report``'s tag histories."""
    return {_strip_digest(d) for d in _all_digests(report)}


def _write_report(report: dict, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output.suffix == ".gz":
        # mtime=0 keeps the gzip bytes reproducible across runs of identical content.
        output.write_bytes(gzip.compress(text.encode("utf-8"), mtime=0))
    else:
        output.write_text(text, encoding="utf-8")
    print(f"Wrote {len(report.get('tags') or {})} tag(s) to {output}", file=sys.stderr)


def _all_digests(report: dict) -> list[str]:
    """Return every retained digest in ``report`` as a full ``sha256:<hex>`` reference."""
    digests: list[str] = []
    for tag_data in (report.get("tags") or {}).values():
        history = tag_data.get("history") if isinstance(tag_data, dict) else None
        if not isinstance(history, list):
            continue
        for entry in history:
            digest = entry.get("d") if isinstance(entry, dict) else None
            if isinstance(digest, str) and digest:
                digests.append(digest if digest.startswith("sha256:") else f"sha256:{digest}")
    return digests


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
        help="Where to write the combined report (default: packaged data/report.json.gz).",
    )
    parser.add_argument(
        "--gzip-output",
        type=Path,
        help="Also write the same combined report (gzipped) to this path (e.g. report.json.gz).",
    )
    parser.add_argument(
        "--prior-url",
        help="URL of the previously published report to merge history from (optional).",
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
    parser.add_argument(
        "--details-inputs",
        nargs="+",
        type=Path,
        default=[],
        help="Per-language details sidecar files to merge into the combined sidecar.",
    )
    parser.add_argument(
        "--details-output",
        type=Path,
        help="Where to write the combined critical+high CVE details sidecar.",
    )
    parser.add_argument(
        "--details-gzip-output",
        type=Path,
        help="Also write the combined details sidecar (gzipped) to this path.",
    )
    parser.add_argument(
        "--details-prior-url",
        help="URL of the previously published details sidecar to merge from (optional).",
    )
    args = parser.parse_args(argv)

    if (args.sbom_src_dir is None) != (args.sbom_out_dir is None):
        parser.error("--sbom-src-dir and --sbom-out-dir must be provided together.")

    payloads: list[dict] = []
    for path in args.inputs:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            print(f"error: cannot read report {path}: {exc}", file=sys.stderr)
            return 1
        body = _decode_report_bytes(raw)
        if body is None:
            print(f"error: cannot decode report {path}", file=sys.stderr)
            return 1
        try:
            payloads.append(json.loads(body))
        except json.JSONDecodeError as exc:
            print(f"error: cannot read report {path}: {exc}", file=sys.stderr)
            return 1

    fresh = merge_reports(payloads)
    prior = fetch_prior_report(args.prior_url) if args.prior_url else None
    combined = merge_with_history(fresh, prior)
    _write_report(combined, args.output)
    if args.gzip_output is not None:
        _write_report(combined, args.gzip_output)
    if args.sbom_src_dir is not None and args.sbom_out_dir is not None:
        copied = publish_sboms(_all_digests(combined), args.sbom_src_dir, args.sbom_out_dir)
        print(f"Published {copied} SBOM(s) to {args.sbom_out_dir}", file=sys.stderr)
    if args.details_output is not None:
        maps = [details_from_sidecar(_read_sidecar(p)) for p in args.details_inputs]
        if args.details_prior_url:
            maps.append(details_from_sidecar(fetch_prior_details(args.details_prior_url)))
        sidecar = build_details_sidecar(
            merge_details(maps), keep_digests=_retained_digests(combined)
        )
        _write_report(sidecar, args.details_output)
        if args.details_gzip_output is not None:
            _write_report(sidecar, args.details_gzip_output)
        print(f"Wrote {len(sidecar['digests'])} digest(s) of details", file=sys.stderr)
    return 0


def _read_sidecar(path: Path) -> dict | None:
    """Read a details sidecar JSON/gz file into a payload dict (``None`` on any failure)."""
    try:
        body = _decode_report_bytes(path.read_bytes())
    except OSError:
        return None
    if body is None:
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


if __name__ == "__main__":
    raise SystemExit(main())
