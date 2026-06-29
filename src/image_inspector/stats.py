"""Read-only stats over the retained scan database (``report.json.gz``).

A **dev-only** helper, intentionally not registered as a console script: run it with
``python -m image_inspector.stats`` (e.g. ``uv run python -m image_inspector.stats``). It
summarises how much is stored in the published/bundled report — total digests, distinct
tags, per-tag depth, active vs. retained history, age range, how many digests are close
to aging out of the retention window, a per-image/per-version breakdown, and the SBOM
count — as a pure read (no scanning).

Because the typed :class:`~image_inspector.report.VulnerabilityReport` flattens history
into a digest index (dropping per-tag depth and each digest's created-at), the
computations here operate on the **raw** report payload dict — the v3 ``tags``/``history``
shape — exactly like :mod:`image_inspector.scanner`.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packaging.version import InvalidVersion, Version
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, ui
from . import report as report_module
from .models import LANGUAGES, Category, Language, VersionScheme
from .report import _decode_report_bytes, _parse_dt, _strip_digest
from .scanner import RETENTION_MAX_AGE_DAYS

DEFAULT_AGING_WITHIN_DAYS = 14

# Image name -> Language, used to attribute a stored ``reference`` to its language/OS.
_LANGUAGE_BY_IMAGE: dict[str, Language] = {lang.image_name: lang for lang in LANGUAGES}
# Stable ordering for the per-image breakdown (the menu order: languages, then OS).
_LANGUAGE_ORDER: dict[str, int] = {lang.key: index for index, lang in enumerate(LANGUAGES)}

_OTHER_KEY = "other"
_OTHER_LABEL = "Other"


@dataclass(frozen=True)
class VersionStats:
    """Tag/digest counts for one version group within an image."""

    version: str
    tags: int
    digests: int
    cves: int = 0


@dataclass(frozen=True)
class ImageStats:
    """Tag/digest counts for one language/OS, with a per-version breakdown."""

    key: str
    label: str
    category: str
    tags: int
    digests: int
    cves: int = 0
    versions: list[VersionStats] = field(default_factory=list)


@dataclass(frozen=True)
class DatabaseStats:
    """A computed summary of the retained scan database."""

    source: str
    generated_at: datetime | None
    trivy_version: str | None
    trivy_db_updated_at: datetime | None
    total_digests: int
    active_digests: int
    retained_digests: int
    distinct_tags: int
    per_tag_min: int
    per_tag_max: int
    per_tag_avg: float
    oldest_created_at: datetime | None
    newest_created_at: datetime | None
    aging_within_days: int
    max_age_days: int
    aging_out_count: int
    sbom_count: int
    total_cves: int | None = None
    by_image: list[ImageStats] = field(default_factory=list)


def _entry_created(entry: dict) -> datetime | None:
    """A history entry's image created-at (``t``) as an aware UTC datetime, or ``None``.

    Naive timestamps are assumed UTC so comparisons against an aware ``now`` never raise.
    """
    value = entry.get("t")
    dt = _parse_dt(value) if isinstance(value, str) else None
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _entry_created_key(entry: dict) -> tuple[bool, datetime, str]:
    """Sort key for newest-``t``-first ordering; undated entries sort last (with reverse)."""
    dt = _entry_created(entry)
    return (dt is not None, dt or datetime.min.replace(tzinfo=UTC), str(entry.get("d") or ""))


def _language_for_reference(reference: str) -> Language | None:
    """Map a ``name:tag`` reference back to its :class:`Language` (``None`` if unknown)."""
    name = reference.rsplit(":", 1)[0]
    return _LANGUAGE_BY_IMAGE.get(name)


def _version_group(reference: str, scheme: VersionScheme) -> str:
    """Group key for a stored tag at the picker's granularity.

    The version token is the part of the tag before the variant suffix (``3.13.14-slim`` ->
    ``3.13.14``). SEMVER tags collapse to ``major.minor`` (``3.13``); MAJOR/CALVER tags use
    the token as-is. Anything unparseable falls back to the raw token.
    """
    tag = reference.rsplit(":", 1)[1]
    token = tag.split("-", 1)[0]
    if scheme is VersionScheme.SEMVER:
        try:
            parsed = Version(token)
        except InvalidVersion:
            return token
        return f"{parsed.major}.{parsed.minor}"
    return token


def _version_sort_key(version: str) -> tuple[int, Version | None, str]:
    """Sort versions newest-first; unparseable versions sort last (then lexically).

    The caller sorts with ``reverse=True``, so parseable versions get the higher leading
    rank (``1``) to land first and unparseable ones get ``0`` to land last.
    """
    try:
        return (1, Version(version), version)
    except InvalidVersion:
        return (0, None, version)


def _sorted_versions(groups: dict[str, dict[str, set]]) -> list[VersionStats]:
    versions = [
        VersionStats(
            version=version,
            tags=len(buckets["tags"]),
            digests=len(buckets["digests"]),
            cves=len(buckets["cves"]),
        )
        for version, buckets in groups.items()
    ]
    versions.sort(key=lambda v: _version_sort_key(v.version), reverse=True)
    return versions


def _image_sort_key(image: ImageStats) -> tuple[int, int, str]:
    """Order known images by the menu order; the ``other`` bucket sorts last."""
    return (
        (0, _LANGUAGE_ORDER[image.key], image.key)
        if image.key in _LANGUAGE_ORDER
        else (
            1,
            0,
            image.label,
        )
    )


def _build_by_image(
    tags: dict[str, dict], digest_cves: dict[str, frozenset[int]]
) -> list[ImageStats]:
    """Group tags by language/OS and, within each, by version (digests = history depth).

    ``digest_cves`` maps a stripped digest to the set of sidecar CVE-record indices affecting
    it; per-image and per-version CVE counts are the distinct records across the group's digests.
    """
    # key -> {"label", "category", "tags": set, "digests": set, "cves": set, "versions": {...}}
    grouped: dict[str, dict] = {}
    for reference, tag_data in tags.items():
        if not isinstance(reference, str) or ":" not in reference:
            continue
        history = tag_data.get("history") if isinstance(tag_data, dict) else None
        if not isinstance(history, list):
            continue
        digests = {entry["d"] for entry in history if isinstance(entry, dict) and entry.get("d")}
        cves: set[int] = set()
        for digest in digests:
            cves |= digest_cves.get(digest, frozenset())
        language = _language_for_reference(reference)
        if language is None:
            key, label, category, version = _OTHER_KEY, _OTHER_LABEL, _OTHER_KEY, reference
        else:
            key, label = language.key, language.label
            category = language.category.value
            version = _version_group(reference, language.scheme)

        bucket = grouped.setdefault(
            key,
            {
                "label": label,
                "category": category,
                "tags": set(),
                "digests": set(),
                "cves": set(),
                "versions": {},
            },
        )
        bucket["tags"].add(reference)
        bucket["digests"].update(digests)
        bucket["cves"].update(cves)
        vbucket = bucket["versions"].setdefault(
            version, {"tags": set(), "digests": set(), "cves": set()}
        )
        vbucket["tags"].add(reference)
        vbucket["digests"].update(digests)
        vbucket["cves"].update(cves)

    result = [
        ImageStats(
            key=key,
            label=bucket["label"],
            category=bucket["category"],
            tags=len(bucket["tags"]),
            digests=len(bucket["digests"]),
            cves=len(bucket["cves"]),
            versions=_sorted_versions(bucket["versions"]),
        )
        for key, bucket in grouped.items()
    ]
    result.sort(key=_image_sort_key)
    return result


def _build_digest_cves(details: dict | None) -> tuple[dict[str, frozenset[int]], int | None]:
    """Map each stripped digest to its sidecar CVE-record indices; return ``(map, total)``.

    ``total`` is the number of critical/high CVE records stored in the sidecar, or ``None``
    when no sidecar was loaded (so the UI can show the CVE data as unavailable).
    """
    if not isinstance(details, dict):
        return {}, None
    vulns = details.get("vulns")
    total = len(vulns) if isinstance(vulns, list) else 0
    digest_cves: dict[str, frozenset[int]] = {}
    raw = details.get("digests")
    if isinstance(raw, dict):
        for digest, indices in raw.items():
            if not isinstance(digest, str) or not isinstance(indices, list):
                continue
            kept = frozenset(i for i in indices if isinstance(i, int) and 0 <= i < total)
            digest_cves[_strip_digest(digest)] = kept
    return digest_cves, total


def compute_stats(
    payload: dict,
    *,
    source: str,
    details: dict | None = None,
    now: datetime | None = None,
    aging_within_days: int = DEFAULT_AGING_WITHIN_DAYS,
    max_age_days: int = RETENTION_MAX_AGE_DAYS,
) -> DatabaseStats:
    """Summarise the retained database described by a raw v3 report ``payload``.

    ``details`` is the optional raw critical/high CVE sidecar payload; when provided, the
    total stored CVE count and per-image/per-version CVE counts are computed from it.
    """
    now = now or datetime.now(UTC)
    tags = payload.get("tags")
    if not isinstance(tags, dict):
        tags = {}
    digest_cves, total_cves = _build_digest_cves(details)

    warn_threshold = timedelta(days=max(max_age_days - aging_within_days, 0))
    aging_out = 0
    depths: list[int] = []
    all_dated: list[datetime] = []
    total_digests = 0
    distinct_tags = 0
    active_digests = 0

    for tag_data in tags.values():
        history = tag_data.get("history") if isinstance(tag_data, dict) else None
        if not isinstance(history, list):
            continue
        entries = [entry for entry in history if isinstance(entry, dict)]
        if not entries:
            continue
        # Newest-created-first, mirroring the retention model: the head is the live pin and
        # a non-head entry's retirement time is its successor's created-at.
        ordered = sorted(entries, key=_entry_created_key, reverse=True)
        distinct_tags += 1
        active_digests += 1
        total_digests += len(ordered)
        depths.append(len(ordered))
        for index, entry in enumerate(ordered):
            created = _entry_created(entry)
            if created is not None:
                all_dated.append(created)
            if index == 0:
                continue  # head never ages out
            superseded_at = _entry_created(ordered[index - 1])
            if superseded_at is not None and now - superseded_at >= warn_threshold:
                aging_out += 1

    return DatabaseStats(
        source=source,
        generated_at=_parse_dt(payload.get("generated_at")),
        trivy_version=payload.get("trivy_version"),
        trivy_db_updated_at=_parse_dt(payload.get("trivy_db_updated_at")),
        total_digests=total_digests,
        active_digests=active_digests,
        retained_digests=total_digests - active_digests,
        distinct_tags=distinct_tags,
        per_tag_min=min(depths) if depths else 0,
        per_tag_max=max(depths) if depths else 0,
        per_tag_avg=round(total_digests / distinct_tags, 1) if distinct_tags else 0.0,
        oldest_created_at=min(all_dated) if all_dated else None,
        newest_created_at=max(all_dated) if all_dated else None,
        aging_within_days=aging_within_days,
        max_age_days=max_age_days,
        aging_out_count=aging_out,
        sbom_count=total_digests,
        total_cves=total_cves,
        by_image=_build_by_image(tags, digest_cves),
    )


def stats_payload(stats: DatabaseStats) -> dict:
    """Build a machine-readable dict describing the stats (for ``--json``)."""
    return {
        "source": stats.source,
        "generated_at": _iso(stats.generated_at),
        "trivy_version": stats.trivy_version,
        "trivy_db_updated_at": _iso(stats.trivy_db_updated_at),
        "digests": {
            "total": stats.total_digests,
            "active": stats.active_digests,
            "retained": stats.retained_digests,
        },
        "tags": {
            "distinct": stats.distinct_tags,
            "per_tag_min": stats.per_tag_min,
            "per_tag_max": stats.per_tag_max,
            "per_tag_avg": stats.per_tag_avg,
        },
        "activity": {
            "oldest_created_at": _iso(stats.oldest_created_at),
            "newest_created_at": _iso(stats.newest_created_at),
        },
        "retention": {
            "max_age_days": stats.max_age_days,
            "aging_within_days": stats.aging_within_days,
            "aging_out": stats.aging_out_count,
        },
        "sboms": {"published": stats.sbom_count},
        "cves": {"total": stats.total_cves},
        "by_image": [
            {
                "key": image.key,
                "label": image.label,
                "category": image.category,
                "tags": image.tags,
                "digests": image.digests,
                "cves": image.cves,
                "versions": [
                    {"version": v.version, "tags": v.tags, "digests": v.digests, "cves": v.cves}
                    for v in image.versions
                ],
            }
            for image in stats.by_image
        ],
    }


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def _load_local_payload() -> dict | None:
    return report_module._load_packaged()


def _load_url_payload() -> dict | None:
    return report_module._fetch_report().payload


def _load_file_payload(path: str) -> dict | None:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    body = _decode_report_bytes(raw)
    if body is None:
        return None
    return report_module._validate_payload(body)


def load_payload(*, source: str, report_path: str | None) -> dict | None:
    """Load a raw report payload for the requested source (``None`` on failure)."""
    if report_path is not None:
        return _load_file_payload(report_path)
    if source == "local":
        return _load_local_payload()
    return _load_url_payload()


def _load_details_file(path: str) -> dict | None:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    body = _decode_report_bytes(raw)
    if body is None:
        return None
    return report_module._validate_details(body)


def load_details_payload(*, source: str, details_path: str | None) -> dict | None:
    """Load the raw critical/high CVE sidecar payload (``None`` when unavailable).

    Mirrors :func:`load_payload`: an explicit ``--details`` file wins, otherwise the bundled
    sidecar (local) or the live published sidecar (url) is used. A missing sidecar is not an
    error — the stats view simply shows the CVE data as unavailable.
    """
    if details_path is not None:
        return _load_details_file(details_path)
    if source == "local":
        return report_module._load_packaged_details()
    return report_module._fetch_details()


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _fmt_dt(dt: datetime | None) -> str:
    return ui.format_datetime(dt)


def _source_label(stats: DatabaseStats, report_path: str | None) -> str:
    if report_path is not None:
        return f"file · {report_path}"
    if stats.source == "local":
        return "local (bundled report.json.gz)"
    url = report_module._report_url()
    return f"url ({url})"


def _summary_rows(stats: DatabaseStats, report_path: str | None) -> list[tuple[str, str, str]]:
    """Section rows as ``(section, label, value)`` for the plain renderer."""
    trivy = stats.trivy_version or "unknown"
    if stats.trivy_db_updated_at is not None:
        trivy += f" · DB {ui.format_date(stats.trivy_db_updated_at)}"
    per_tag = f"min {stats.per_tag_min} · max {stats.per_tag_max} · avg {stats.per_tag_avg}"
    aging = f"{stats.aging_out_count} ⚠" if stats.aging_out_count else "0"
    cve_total = "unavailable" if stats.total_cves is None else str(stats.total_cves)
    return [
        ("REPORT", "Source", _source_label(stats, report_path)),
        ("REPORT", "Generated", _fmt_dt(stats.generated_at)),
        ("REPORT", "Trivy", trivy),
        ("DIGESTS", "Total", str(stats.total_digests)),
        ("DIGESTS", "Active (current)", str(stats.active_digests)),
        ("DIGESTS", "Retained (history)", str(stats.retained_digests)),
        ("TAGS", "Distinct tags", str(stats.distinct_tags)),
        ("TAGS", "Digests per tag", per_tag),
        ("CVES", "Stored (critical/high)", cve_total),
        ("ACTIVITY", "Oldest created", _fmt_dt(stats.oldest_created_at)),
        ("ACTIVITY", "Newest created", _fmt_dt(stats.newest_created_at)),
        ("RETENTION", "Window", f"{stats.max_age_days} days"),
        ("RETENTION", f"Aging out ≤ {stats.aging_within_days} days", aging),
        ("SBOMS", "Published", str(stats.sbom_count)),
    ]


def _aging_style(stats: DatabaseStats) -> str:
    return "orange" if stats.aging_out_count else "ok"


def _render_plain(stats: DatabaseStats, report_path: str | None) -> None:
    """Uncolored, sectioned ``key: value`` output (for ``--plain``/``NO_COLOR``)."""
    sections: dict[str, list[tuple[str, str]]] = {}
    order: list[str] = []
    for section, label, value in _summary_rows(stats, report_path):
        if section not in sections:
            sections[section] = []
            order.append(section)
        sections[section].append((label, value))

    console = ui.console
    for section in order:
        console.print(section)
        width = max(len(label) for label, _ in sections[section])
        for label, value in sections[section]:
            console.print(f"  {label.ljust(width)}  {value}")
        console.print()

    cves_available = stats.total_cves is not None
    console.print("BY IMAGE")
    for image in stats.by_image:
        cve = f" · {image.cves} CVEs" if cves_available else ""
        console.print(f"  {image.label}  ({image.tags} tags · {image.digests} digests{cve})")
        for version in image.versions:
            vcve = f" · {version.cves} CVEs" if cves_available else ""
            console.print(
                f"    {version.version.ljust(10)}  "
                f"{version.tags} tags · {version.digests} digests{vcve}"
            )
    console.print()


def _render_rich(stats: DatabaseStats, report_path: str | None) -> None:
    """Polished rich panel matching the picker's result look."""
    sections: dict[str, list[tuple[str, str]]] = {}
    order: list[str] = []
    for section, label, value in _summary_rows(stats, report_path):
        if section not in sections:
            sections[section] = []
            order.append(section)
        sections[section].append((label, value))

    blocks: list[RenderableType] = []
    for section in order:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="label", justify="left")
        grid.add_column(style="value")
        for label, value in sections[section]:
            if section == "RETENTION" and label.startswith("Aging out"):
                grid.add_row(label, Text(value, style=_aging_style(stats)))
            else:
                grid.add_row(label, value)
        blocks.append(Text(section, style="muted"))
        blocks.append(Padding(grid, (0, 0, 1, 2)))

    blocks.append(Text("BY IMAGE", style="muted"))
    blocks.append(Padding(_by_image_table(stats), (0, 0, 0, 2)))

    ui.console.print(
        Panel(
            Group(*blocks),
            title="[accent]📊 database stats",
            border_style="accent",
            padding=(1, 2),
        )
    )


def _by_image_table(stats: DatabaseStats) -> Table:
    table = Table(
        box=None,
        show_edge=False,
        show_header=True,
        header_style="muted",
        pad_edge=False,
        padding=(0, 3, 0, 0),
    )
    cves_available = stats.total_cves is not None
    table.add_column("Image", style="label")
    table.add_column("Version", style="muted")
    table.add_column("Tags", justify="right", style="value")
    table.add_column("Digests", justify="right", style="value")
    table.add_column("CVEs", justify="right", style="value")

    def cve_cell(count: int) -> str:
        return str(count) if cves_available else "—"

    last_category: str | None = None
    for image in stats.by_image:
        if image.category != last_category:
            heading = (
                "Languages"
                if image.category == Category.LANGUAGE.value
                else ("OS" if image.category == Category.OS.value else "Other")
            )
            table.add_row(Text(heading, style="accent"), "", "", "", "")
            last_category = image.category
        table.add_row(
            Text(f"  {image.label}", style="label"),
            "",
            str(image.tags),
            str(image.digests),
            cve_cell(image.cves),
        )
        for version in image.versions:
            table.add_row(
                "",
                f"  {version.version}",
                str(version.tags),
                str(version.digests),
                cve_cell(version.cves),
            )
    return table


def render(stats: DatabaseStats, *, plain: bool, report_path: str | None) -> None:
    """Render ``stats`` to the configured console (rich, or plain when requested)."""
    if plain:
        _render_plain(stats, report_path)
    else:
        _render_rich(stats, report_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="image-inspector-stats",
        description="Read-only stats over the retained scan database (dev-only).",
    )
    parser.add_argument(
        "--app-version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the image-inspector version and exit",
    )
    parser.add_argument(
        "--source",
        choices=("local", "url"),
        default="url",
        help="read the bundled report (local) or the live published report (url, default)",
    )
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="read a specific report.json[.gz] file directly (overrides --source)",
    )
    parser.add_argument(
        "--details",
        metavar="PATH",
        help="read a specific details sidecar (critical/high CVEs) file directly",
    )
    parser.add_argument(
        "--aging-within",
        type=int,
        default=DEFAULT_AGING_WITHIN_DAYS,
        metavar="N",
        help=f"flag digests within N days of aging out (default: {DEFAULT_AGING_WITHIN_DAYS})",
    )
    parser.add_argument("--json", action="store_true", help="emit stats as JSON")
    parser.add_argument("--plain", action="store_true", help="plain, uncolored output")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m image_inspector.stats``. Returns an exit code."""
    args = _build_parser().parse_args(argv)

    if args.aging_within < 0:
        ui.configure(plain=args.plain)
        ui.error("--aging-within must be zero or greater.")
        return 2

    payload = load_payload(source=args.source, report_path=args.report)
    if payload is None:
        ui.configure(plain=args.plain)
        target = args.report or (args.source if args.source == "local" else "the published report")
        ui.error(f"Could not load a usable report from {target}.")
        return 1

    details = load_details_payload(source=args.source, details_path=args.details)

    stats = compute_stats(
        payload,
        source="file" if args.report else args.source,
        details=details,
        aging_within_days=args.aging_within,
    )

    if args.json:
        print(json.dumps(stats_payload(stats), indent=2))
        return 0

    ui.configure(plain=args.plain)
    render(stats, plain=args.plain, report_path=args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
