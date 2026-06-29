"""Modern terminal UI: themed banner, arrow-key prompts, spinners, result panel."""

from __future__ import annotations

import base64
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime
from enum import StrEnum
from typing import Any

import pyfiglet
import questionary
from packaging.version import InvalidVersion, Version
from questionary import Choice, Separator, Style
from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import __version__
from .inspection import StageInspection, StageStatus
from .models import Category, Language, ResolvedImage, ScanSource
from .report import ImageVulnerabilities, ReportSource, Vulnerability, VulnerabilityReport

_THEME = Theme(
    {
        "accent": "bold cyan",
        "muted": "grey58",
        "label": "bold white",
        "value": "bright_cyan",
        "ok": "bold green",
        "warn": "bold yellow",
        "orange": "bold #ff8c00",
        "err": "bold red",
    }
)


def _build_console(plain: bool) -> Console:
    """Build a console; disable color for ``--plain`` or when ``NO_COLOR`` is set."""
    no_color = plain or bool(os.environ.get("NO_COLOR"))
    return Console(theme=_THEME, no_color=no_color)


def _ensure_utf8_stream(stream: object) -> None:
    """Switch a text stream to UTF-8 so emoji/unicode never crash legacy consoles."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    with suppress(ValueError, OSError):
        reconfigure(encoding="utf-8", errors="replace")


console = _build_console(plain=False)
_PLAIN = False


def configure(*, plain: bool = False) -> None:
    """Configure the shared console for plain/no-color output."""
    global console, _PLAIN
    _PLAIN = plain
    _ensure_utf8_stream(sys.stdout)
    _ensure_utf8_stream(sys.stderr)
    console = _build_console(plain=plain)


# questionary menu styling kept visually consistent with the rich theme.
_PROMPT_STYLE = Style(
    [
        ("qmark", "fg:#22d3ee bold"),
        ("question", "bold"),
        ("pointer", "fg:#22d3ee bold"),
        ("highlighted", "fg:#22d3ee bold"),
        ("selected", "fg:#22d3ee"),
        ("answer", "fg:#22d3ee bold"),
        ("instruction", "fg:#6b7280"),
        ("separator", "fg:#f59e0b bold"),
        ("disabled", "fg:#6b7280 italic"),
    ]
)


def _two_tone_wordmark() -> tuple[Text, int]:
    """Render the figlet wordmark (white ``image``, orange ``inspector``).

    Returns the rendered art and the total block width in cells.
    """
    words = (("image", "label"), ("inspector", "orange"))
    rendered = []
    for word, style in words:
        lines = pyfiglet.figlet_format(word, font="small").rstrip("\n").split("\n")
        width = max((len(line) for line in lines), default=0)
        rendered.append(([line.ljust(width) for line in lines], style, width))
    height = max(len(lines) for lines, _, _ in rendered)
    total_width = sum(width for _, _, width in rendered) + (len(rendered) - 1)

    art = Text()
    for row in range(height):
        for index, (lines, style, _) in enumerate(rendered):
            if index:
                art.append(" ")
            art.append(lines[row] if row < len(lines) else "", style=style)
        if row < height - 1:
            art.append("\n")
    return art, total_width


def banner() -> None:
    """Print the branded launch banner inside a bordered panel."""
    wordmark, width = _two_tone_wordmark()
    tagline, version = "select • inspect • pin", f"v{__version__}"

    # Center the tagline across the full block width while pinning the version
    # to the right edge.
    left_pad = max((width - len(tagline)) // 2, 0)
    version_start = max(width - len(version), left_pad + len(tagline) + 1)
    mid_gap = version_start - (left_pad + len(tagline))

    footer = Text()
    footer.append(" " * left_pad)
    footer.append(tagline, style="accent")
    footer.append(" " * mid_gap)
    footer.append(version, style="muted")

    # Fixed-width column keeps the footer's right edge aligned with the wordmark.
    block = Table.grid()
    block.add_column(width=width)
    block.add_row(wordmark)
    block.add_row(footer)

    console.print(Panel(Align.center(block), border_style="accent", padding=(0, 2, 1, 2)))


@contextmanager
def working(message: str) -> Iterator[None]:
    """Show an animated spinner while a block of work runs."""
    with console.status(f"[accent]{message}", spinner="dots"):
        yield


def _ask(message: str, choices: list) -> Any:
    """Run an arrow-key select; return ``None`` if the user cancels."""
    return questionary.select(
        message,
        choices=choices,
        style=_PROMPT_STYLE,
        qmark="›",
        instruction="(↑/↓ then Enter)",
    ).ask()


_CATEGORY_HEADINGS = (
    (Category.LANGUAGE, "Languages & runtimes"),
    (Category.OS, "OS base images"),
)


def select_language(languages: tuple[Language, ...]) -> Language | None:
    """Prompt for a language/runtime or OS base image, grouped by category."""
    choices: list = []
    for category, heading in _CATEGORY_HEADINGS:
        group = [lang for lang in languages if lang.category is category]
        if not group:
            continue
        choices.append(Separator(f"── {heading.upper()} ──"))
        choices.extend(Choice(title=lang.label, value=lang) for lang in group)
    return _ask("Select a language or OS", choices)


def select_version(versions: list[str], lts_versions: frozenset[str] = frozenset()) -> str | None:
    """Prompt for a version; releases in ``lts_versions`` are marked as LTS."""
    choices = [
        Choice(
            title=f"{version}  ·  LTS" if version in lts_versions else version,
            value=version,
        )
        for version in versions
    ]
    return _ask("Select a version", choices)


def select_variant(variants: list[str]) -> str | None:
    """Prompt for an image variant (slim, alpine, ...)."""
    choices = [Choice(title=variant, value=variant) for variant in variants]
    return _ask("Select a variant", choices)


def format_size(num_bytes: int | None) -> str:
    """Render a byte count as a human-readable string (e.g. ``19.4 MB``).

    Uses base-1024 with familiar KB/MB/GB labels.
    """
    if num_bytes is None:
        return "unknown"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024.0 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GB"


def format_datetime(dt: datetime | None) -> str:
    """Render a timestamp as a human-readable string, e.g. ``Sep 10, 2024 · 13:50 UTC``."""
    if dt is None:
        return "unknown"
    base = dt.strftime("%b ") + f"{dt.day}, " + dt.strftime("%Y · %H:%M")
    tz = dt.strftime("%Z")
    return f"{base} {tz}".strip() if tz else base


def format_date(dt: datetime | None) -> str:
    """Render just the date portion of a timestamp, e.g. ``Sep 10, 2024``."""
    if dt is None:
        return "unknown"
    return dt.strftime("%b ") + f"{dt.day}, " + dt.strftime("%Y")


def format_vulnerabilities(vulns: ImageVulnerabilities | None) -> Text:
    """Render vulnerability counts as a styled line for the result panel."""
    if vulns is None:
        return Text("no scan data", style="muted")

    critical_style = "err" if vulns.critical else "ok"
    high_style = "orange" if vulns.high else "ok"
    total_style = "warn" if vulns.total else "ok"

    line = Text()
    line.append(f"Critical: {vulns.critical}", style=critical_style)
    line.append("  ·  ")
    line.append(f"High: {vulns.high}", style=high_style)
    line.append("  ·  ")
    line.append(f"Total: {vulns.total}", style=total_style)
    return line


def format_scan_source(source: ScanSource | None) -> str | None:
    """Render the scan provenance line, e.g. ``Trivy v0.71.1 · DB Jun 14, 2026``.

    Returns ``None`` when no scanner version is known (the row is then omitted).
    """
    if source is None or source.version is None:
        return None
    label = f"Trivy v{source.version}"
    if source.db_updated_at is not None:
        label += f" · DB {format_date(source.db_updated_at)}"
    return label


def format_data_source(source: ReportSource | None) -> str:
    """Render the data-origin line for the SECURITY panel's ``Source`` row.

    ``ONLINE`` → fresh data fetched online; ``OFFLINE`` → the packaged snapshot;
    ``OUTDATED`` → the packaged snapshot served because the online report is newer than
    this build understands (the tool is behind); ``None`` → no report was available.
    """
    if source is ReportSource.ONLINE:
        return "online (latest)"
    if source is ReportSource.OFFLINE:
        return "offline (bundled copy)"
    if source is ReportSource.OUTDATED:
        return "bundled (tool outdated)"
    return "not found"


_DISTRIBUTION_NAME = "base-image-inspector"


_STATUS_LABELS: dict[StageStatus, str] = {
    StageStatus.PINNED_KNOWN: "pinned digest tracked",
    StageStatus.PINNED_UNKNOWN: "pinned digest not tracked",
    StageStatus.TAG_KNOWN: "tag tracked (no digest pinned)",
    StageStatus.UNTRACKED: "not tracked",
    StageStatus.SKIPPED: "skipped",
}

_SEVERITY_WORDS = {"C": "critical", "H": "high"}


def _severity_word(sev: str) -> str | None:
    """Map a compact severity code to its word: ``C``→critical, ``H``→high.

    Any other non-empty code is returned verbatim (so unexpected values surface rather than
    being silently dropped); an empty code yields ``None``.
    """
    return _SEVERITY_WORDS.get(sev) or (sev or None)


def _format_cve(vuln: Vulnerability) -> str:
    """Render a single C/H CVE, e.g. ``CVE-… (critical, openssl → fixed in 3.3.2)``.

    The fixed version is appended when known, so still-present CVEs show the upgrade target.
    """
    severity = _severity_word(vuln.sev) or "?"
    package = f", {vuln.pkg}" if vuln.pkg else ""
    fix = f" → fixed in {vuln.fix}" if vuln.fix else ""
    return f"{vuln.id} ({severity}{package}{fix})"


def _cve_style(vuln: Vulnerability) -> str:
    """Theme style for a CVE line: red for critical, orange for high, muted otherwise."""
    if vuln.sev == "C":
        return "err"
    if vuln.sev == "H":
        return "orange"
    return "muted"


def _cve_detail_value(cves: tuple[Vulnerability, ...]) -> Text:
    """Build the aligned critical/high CVE table as a single multi-line value.

    Columns are severity, CVE id, package, and fix status. The first line is a muted column
    header; each data line is tinted by severity (red critical, orange high). Returned as one
    ``Text`` so it sits in the value column, aligned with the other SECURITY rows.
    """
    headers = ("SEVERITY", "CVE", "PACKAGE", "FIX")
    cells = [
        (
            _severity_word(v.sev) or "?",
            v.id,
            v.pkg or "-",
            f"upgrade to {v.fix}" if v.fix else "no fix yet",
        )
        for v in cves
    ]
    widths = [max(len(headers[i]), *(len(row[i]) for row in cells)) for i in range(len(headers))]

    def _line(parts: tuple[str, ...]) -> str:
        return "  ".join(p.ljust(widths[i]) for i, p in enumerate(parts)).rstrip()

    value = Text(_line(headers), style="muted")
    for v, cell in zip(cves, cells, strict=True):
        value.append("\n")
        value.append(_line(cell), style=_cve_style(v))
    return value


def _cve_payload(vuln: Vulnerability) -> dict:
    """Serialise a critical/high CVE for the machine-readable ``--json`` output."""
    return {
        "id": vuln.id,
        "package": vuln.pkg or None,
        "severity": _severity_word(vuln.sev),
        "fixed_version": vuln.fix,
    }


def _inspection_row(label: str, value: Text | str, *, width: int = 8) -> None:
    """Print one indented ``label  value`` line of a stage report."""
    line = Text(f"    {label.ljust(width)}  ", style="muted")
    line.append(value if isinstance(value, Text) else Text(str(value), style="value"))
    console.print(line)


def _full_digest(digest: str | None) -> str | None:
    """Normalise a digest to the full ``sha256:<hex>`` form for ``--json``; ``None`` if absent."""
    if not digest:
        return None
    body = digest.split(":", 1)[1] if ":" in digest else digest
    return f"sha256:{body}"


def _stage_has_data(inspection: StageInspection) -> bool:
    """Whether the stage has any tracked counts (pinned or latest) to compare."""
    return inspection.pinned_counts is not None or inspection.latest_counts is not None


def _pinned_vulnerable(inspection: StageInspection) -> bool:
    """Whether the pinned digest carries any critical/high findings."""
    counts = inspection.pinned_counts
    return counts is not None and (counts.critical > 0 or counts.high > 0)


def _latest_is_cleaner(inspection: StageInspection) -> bool:
    """Whether the latest digest has fewer critical+high findings than the pinned one."""
    pinned, latest = inspection.pinned_counts, inspection.latest_counts
    if pinned is None or latest is None:
        return False
    return (latest.critical + latest.high) < (pinned.critical + pinned.high)


def _status_style(inspection: StageInspection) -> str:
    """Theme style for a stage's status line."""
    if inspection.status is StageStatus.SKIPPED:
        return "muted"
    if inspection.status in (StageStatus.UNTRACKED, StageStatus.PINNED_UNKNOWN):
        return "warn"
    if _pinned_vulnerable(inspection):
        return "warn"
    return "ok"


def _stage_title(inspection: StageInspection) -> Text:
    """Build the ``[n] FROM … [AS alias]`` header for a stage."""
    stage = inspection.stage
    title = Text()
    title.append(f"[{stage.index + 1}] ", style="muted")
    title.append(f"FROM {stage.raw}", style="label")
    if stage.alias:
        title.append(f" AS {stage.alias}", style="muted")
    return title


def _cve_list_text(vulns: tuple[Vulnerability, ...]) -> Text:
    """Render a comma-separated, per-severity-coloured list of CVEs."""
    text = Text()
    for index, vuln in enumerate(vulns):
        if index:
            text.append(", ")
        text.append(_format_cve(vuln), style=_cve_style(vuln))
    return text


def _movement_text(pinned: ImageVulnerabilities, latest: ImageVulnerabilities | None) -> Text:
    """Render the medium/low/unknown count movement (counts only, no per-CVE detail)."""
    before = pinned.medium + pinned.low + pinned.unknown
    text = Text()
    if latest is None:
        text.append(str(before), style="muted")
    else:
        after = latest.medium + latest.low + latest.unknown
        text.append(f"{before} → {after}", style="ok" if after < before else "muted")
    text.append("  (count only — no CVE detail)", style="muted")
    return text


def _fix_diff_rows(inspection: StageInspection) -> list[tuple[str, Text]]:
    """Build the critical/high fix-diff + medium/low movement rows for a tracked pinned image."""
    if inspection.status is not StageStatus.PINNED_KNOWN or inspection.latest_counts is None:
        return []
    rows: list[tuple[str, Text]] = []
    fixed, still = inspection.fixed, inspection.still_present
    if not fixed and not still:
        rows.append(("fix-diff", Text("no critical/high CVEs to compare", style="ok")))
    else:
        summary = Text()
        summary.append(
            f"latest fixes {len(fixed)} of your critical/high CVE(s)",
            style="ok" if fixed else "muted",
        )
        summary.append(", ")
        summary.append(f"{len(still)} still present", style="warn" if still else "ok")
        rows.append(("fix-diff", summary))
        if fixed:
            rows.append(("fixed", _cve_list_text(fixed)))
        if still:
            rows.append(("still", _cve_list_text(still)))
    if inspection.pinned_counts is not None:
        rows.append(("med/low", _movement_text(inspection.pinned_counts, inspection.latest_counts)))
    rows.append(("detail", Text("per-CVE detail: critical/high only", style="muted")))
    return rows


def _stage_head_rows(inspection: StageInspection) -> list[tuple[str, Text]]:
    """Build the status (+ pinned-digest vulnerability count) rows for a stage."""
    rows: list[tuple[str, Text]] = []
    status = _STATUS_LABELS[inspection.status]
    if inspection.note:
        status = f"{status} — {inspection.note}"
    rows.append(("status", Text(status, style=_status_style(inspection))))
    if inspection.pinned_digest:
        rows.append(("pinned", format_vulnerabilities(inspection.pinned_counts)))
    return rows


def _latest_section_rows(inspection: StageInspection) -> list[tuple[str, Text]]:
    """Build the ``latest digest`` section: vulnerability count, created date, full FROM line."""
    if inspection.latest_counts is None and not inspection.latest_digest:
        return []
    vulns = format_vulnerabilities(inspection.latest_counts)
    if _latest_is_cleaner(inspection):
        vulns = vulns.copy()
        vulns.append("  ✓ cleaner", style="ok")
    rows: list[tuple[str, Text]] = [
        ("vulnerabilities", vulns),
        ("created", Text(format_datetime(inspection.latest_created), style="value")),
    ]
    full = _full_digest(inspection.latest_digest)
    if full and inspection.reference:
        rows.append(("FROM", Text(f"{inspection.reference}@{full}", style="value")))
    return rows


def _stage_sections(inspection: StageInspection) -> list[tuple[str | None, list[tuple[str, Text]]]]:
    """Build a stage's ``(section title, rows)`` groups, dropping empty sections.

    The leading group (status + pinned count) has no title; the ``latest digest`` and
    ``differences`` groups are titled. Shared by the rich and plain renderers.
    """
    sections: list[tuple[str | None, list[tuple[str, Text]]]] = [
        (None, _stage_head_rows(inspection)),
        ("latest digest", _latest_section_rows(inspection)),
        ("differences", _fix_diff_rows(inspection)),
    ]
    return [(title, rows) for title, rows in sections if rows]


def _rows_grid(rows: list[tuple[str, Text]]) -> Table:
    """Build a two-column ``label  value`` grid for one stage section."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="label", justify="left")
    grid.add_column()
    for label, value in rows:
        grid.add_row(label, value)
    return grid


def _render_dockerfile_plain(path: str, inspections: list[StageInspection]) -> None:
    """Print the Dockerfile inspection as plain, sectioned text (no borders)."""
    console.print("DOCKERFILE")
    _inspection_row("Path", path)
    _inspection_row("Stages", f"{len(inspections)} FROM instruction(s)")
    if not inspections:
        _inspection_row("", "No FROM instructions found.")
        return
    for inspection in inspections:
        console.print()
        console.print(_stage_title(inspection))
        for title, rows in _stage_sections(inspection):
            if title:
                console.print(f"  {title}")
            width = max(len(label) for label, _ in rows)
            for label, value in rows:
                _inspection_row(label, value, width=width)


def render_dockerfile_inspection(path: str, inspections: list[StageInspection]) -> None:
    """Render a Dockerfile's per-``FROM`` pinned-vs-latest comparison.

    All stages live in a single ``✓ dockerfile`` panel that opens with a ``DOCKERFILE``
    section (path + stage count), then one block per ``FROM`` image. Each stage shows its
    status and pinned-digest vulnerability count, a ``latest digest`` section (vulnerability
    count, when it was published, and the full copy-paste ``FROM`` line), and a
    ``differences`` section. Falls back to plain, sectioned text for ``--plain`` /
    ``NO_COLOR``. Per-CVE detail is critical/high only; medium/low/unknown findings are
    shown as count movement.
    """
    if _PLAIN:
        _render_dockerfile_plain(path, inspections)
        return

    blocks: list[RenderableType] = [Text("DOCKERFILE", style="muted")]
    header = Table.grid(padding=(0, 2))
    header.add_column(style="label", justify="left")
    header.add_column(style="value")
    header.add_row("Path", path)
    header.add_row("Stages", f"{len(inspections)} FROM instruction(s)")
    blocks.append(Padding(header, (0, 0, 1, 2)))

    if not inspections:
        blocks.append(Padding(Text("No FROM instructions found.", style="muted"), (0, 0, 0, 2)))
    for inspection in inspections:
        blocks.append(_stage_title(inspection))
        for title, rows in _stage_sections(inspection):
            if title:
                blocks.append(Text(title, style="muted"))
            blocks.append(Padding(_rows_grid(rows), (0, 0, 1, 2)))

    console.print(
        Panel(
            Group(*blocks),
            title="[ok]✓ dockerfile",
            border_style="ok",
            padding=(1, 2),
        )
    )


def _counts_payload(counts: ImageVulnerabilities | None) -> dict | None:
    """Serialise vulnerability counts for ``--json``; ``None`` when unscanned."""
    if counts is None:
        return None
    return {
        "critical": counts.critical,
        "high": counts.high,
        "medium": counts.medium,
        "low": counts.low,
        "unknown": counts.unknown,
        "total": counts.total,
        "scanned_at": counts.scanned_at.isoformat() if counts.scanned_at else None,
    }


def _stage_payload(inspection: StageInspection) -> dict:
    """Serialise one stage's pinned-vs-latest comparison for ``--dockerfile --json``."""
    stage = inspection.stage
    return {
        "index": stage.index,
        "from": f"FROM {stage.raw}",
        "raw": stage.raw,
        "image": stage.image,
        "tag": stage.tag,
        "alias": stage.alias,
        "reference": inspection.reference,
        "references_stage": stage.references_stage,
        "status": inspection.status.value,
        "note": inspection.note,
        "pinned": {
            "digest": _full_digest(inspection.pinned_digest),
            "vulnerabilities": _counts_payload(inspection.pinned_counts),
        },
        "latest": {
            "digest": _full_digest(inspection.latest_digest),
            "created": inspection.latest_created.isoformat() if inspection.latest_created else None,
            "vulnerabilities": _counts_payload(inspection.latest_counts),
        },
        "critical_high": {
            "detail_scope": "critical_high_only",
            "fixed": [_cve_payload(v) for v in inspection.fixed],
            "still_present": [_cve_payload(v) for v in inspection.still_present],
        },
        "flags": {
            "has_data": _stage_has_data(inspection),
            "pinned_vulnerable": _pinned_vulnerable(inspection),
            "latest_is_cleaner": _latest_is_cleaner(inspection),
        },
    }


def dockerfile_payload(
    path: str, inspections: list[StageInspection], report: VulnerabilityReport
) -> dict:
    """Build the stable machine-readable payload for the ``--dockerfile --json`` flow."""
    return {
        "dockerfile": path,
        "generated_at": report.generated_at.isoformat() if report.generated_at else None,
        "data_source": report.source.value if report.source else None,
        "scanner": {
            "name": "trivy",
            "version": report.trivy_version,
            "db_updated_at": report.trivy_db_updated_at.isoformat()
            if report.trivy_db_updated_at
            else None,
        },
        "stage_count": len(inspections),
        "stages": [_stage_payload(inspection) for inspection in inspections],
    }


def show_dockerfile_inspection_json(
    path: str, inspections: list[StageInspection], report: VulnerabilityReport
) -> None:
    """Emit the Dockerfile inspection as a single JSON object on stdout."""
    print(json.dumps(dockerfile_payload(path, inspections, report), indent=2))


class Installer(StrEnum):
    """How the running tool was most likely installed (drives the upgrade hint)."""

    UV_TOOL = "uv-tool"
    UVX = "uvx"
    PIPX = "pipx"
    PIP = "pip"


_UPGRADE_COMMANDS: dict[Installer, str] = {
    Installer.UV_TOOL: f"uv tool upgrade {_DISTRIBUTION_NAME}",
    Installer.UVX: f"uvx --from {_DISTRIBUTION_NAME}@latest image-inspector",
    Installer.PIPX: f"pipx upgrade {_DISTRIBUTION_NAME}",
    Installer.PIP: f"pip install --upgrade {_DISTRIBUTION_NAME}",
}


def detect_installer(path: str | None = None) -> Installer:
    """Best-effort guess of how the tool was installed, from its on-disk location.

    Inspects the installed package path (this module's own ``__file__`` by default), whose
    directory layout reveals the installer: ``.../uv/tools/...`` for ``uv tool install``,
    the uv cache (``.../uv/cache/archive-v0/...``) for an ephemeral ``uvx`` run, and a
    ``pipx`` segment for pipx. Anything else falls back to plain ``pip``.
    """
    parts = (path if path is not None else __file__).replace("\\", "/").lower().split("/")
    if "uv" in parts and "tools" in parts:
        return Installer.UV_TOOL
    if "uv" in parts and ("cache" in parts or "archive-v0" in parts):
        return Installer.UVX
    if "pipx" in parts:
        return Installer.PIPX
    return Installer.PIP


def upgrade_command(path: str | None = None) -> str:
    """Return the installer-appropriate command to fetch the newest release."""
    return _UPGRADE_COMMANDS[detect_installer(path)]


def _is_newer(latest: str | None, installed: str) -> bool:
    """Return ``True`` if ``latest`` is a strictly newer version than ``installed``.

    Offline/unknown-safe: a missing ``latest`` or any unparsable version returns ``False``.
    """
    if not latest:
        return False
    try:
        return Version(latest) > Version(installed)
    except InvalidVersion:
        return False


def _append_update_line(text: Text, latest_version: str) -> None:
    """Append the shared "New version vX is available" call-to-action to ``text``.

    The upgrade command goes on its own line so it stands out and is easy to copy.
    """
    text.append("New version ")
    text.append(f"v{latest_version}", style="label")
    text.append(" is available. Run:\n    ")
    text.append(upgrade_command(), style="value")


def format_update_notice(installed_version: str, latest_version: str | None) -> Text | None:
    """Build the light "a new version is available" line, or ``None`` if up to date.

    Used when the report itself is fine but PyPI advertises a newer tool release.
    """
    if not _is_newer(latest_version, installed_version):
        return None
    assert latest_version is not None
    notice = Text()
    _append_update_line(notice, latest_version)
    return notice


def format_outdated_warning(
    generated_at: datetime | None,
    installed_version: str,
    latest_version: str | None,
) -> Text:
    """Build the strong warning shown when the report source is ``OUTDATED``.

    The online report is newer than this build supports, so we are serving the bundled,
    stale copy. When PyPI confirms a newer release exists, point the user at the
    installer-appropriate upgrade command; otherwise (the matching release isn't published
    yet, or PyPI is unreachable) tell them a new version is coming soon — never to update.
    """
    warning = Text()
    warning.append(
        "This version can't read the latest security data, image-inspector will use ",
        style="warn",
    )
    warning.append("outdated", style="err")
    warning.append(f" copy from {format_date(generated_at)}.\n", style="warn")
    if _is_newer(latest_version, installed_version):
        assert latest_version is not None
        _append_update_line(warning, latest_version)
    else:
        warning.append("A new version will be available soon.", style="warn")
    return warning


def show_version_status(
    report_source: ReportSource | None,
    generated_at: datetime | None,
    installed_version: str,
    latest_version: str | None,
) -> None:
    """Print the outdated-report warning or the lighter update notice, if either applies.

    An ``OUTDATED`` report always takes precedence (its data is stale); otherwise a newer
    PyPI release surfaces the light update notice. Both are shown in a compact, bordered
    panel so they stand out; prints nothing when fully up to date.
    """
    if report_source is ReportSource.OUTDATED:
        console.print(
            Panel(
                format_outdated_warning(generated_at, installed_version, latest_version),
                title="[err]⚠  OUTDATED SECURITY DATA[/err]",
                title_align="left",
                border_style="err",
                padding=(0, 2),
                expand=True,
            )
        )
        return
    notice = format_update_notice(installed_version, latest_version)
    if notice is not None:
        console.print(
            Panel(
                notice,
                title="[accent]⬆  UPDATE AVAILABLE[/accent]",
                title_align="left",
                border_style="accent",
                padding=(0, 2),
                expand=True,
            )
        )


def _result_sections(image: ResolvedImage) -> list[tuple[str, list[tuple[str, str | Text]]]]:
    """Group the resolved-image details into labelled (title, rows) sections."""
    vulns = image.vulnerabilities
    security: list[tuple[str, str | Text]] = [
        ("Vulnerabilities", format_vulnerabilities(vulns)),
    ]
    if vulns is not None and vulns.scanned_at is not None:
        security.append(("Scanned", format_datetime(vulns.scanned_at)))
    scanner = format_scan_source(image.scan_source)
    if scanner is not None:
        security.append(("Scanner", scanner))
    security.append(("Source", format_data_source(image.report_source)))
    if image.cve_details:
        security.append(("CVEs", _cve_detail_value(image.cve_details)))

    return [
        ("SELECTED", [("", image.source_label)]),
        (
            "IMAGE",
            [
                ("Image", image.reference),
                ("Created", format_datetime(image.created)),
                ("Download", f"{format_size(image.size)} (compressed, linux/amd64)"),
                ("Digest", image.digest),
            ],
        ),
        ("SECURITY", security),
    ]


def result_payload(image: ResolvedImage) -> dict:
    """Build a machine-readable dict describing the resolved image."""
    vulns = image.vulnerabilities
    source = image.scan_source
    return {
        "source": image.source_label,
        "language": image.language.key,
        "version": image.version,
        "variant": image.variant,
        "is_lts": image.is_lts,
        "image": image.reference,
        "pinned_reference": image.pinned_reference,
        "digest": image.digest,
        "created": image.created.isoformat() if image.created else None,
        "size_bytes": image.size,
        "from_line": f"FROM {image.pinned_reference}",
        "vulnerabilities": _counts_payload(vulns),
        "critical_high_cves": [_cve_payload(v) for v in image.cve_details],
        "scanner": {
            "name": "trivy",
            "version": source.version if source else None,
            "db_updated_at": source.db_updated_at.isoformat()
            if source and source.db_updated_at
            else None,
        },
        "data_source": image.report_source.value if image.report_source else None,
    }


def show_result_json(image: ResolvedImage) -> None:
    """Emit the resolved image as a single JSON object on stdout."""
    print(json.dumps(result_payload(image), indent=2))


def _show_result_plain(image: ResolvedImage) -> None:
    """Render the result as uncolored, sectioned ``key: value`` lines."""
    for title, rows in _result_sections(image):
        console.print(title)
        width = max((len(label) for label, _ in rows if label), default=0)
        for label, value in rows:
            text = value.plain if isinstance(value, Text) else str(value)
            lines = text.split("\n")
            if label:
                console.print(f"  {label.ljust(width)}  {lines[0]}")
                indent = " " * (2 + width + 2)
                for cont in lines[1:]:
                    console.print(f"{indent}{cont}")
            else:
                for line in lines:
                    console.print(f"  {line}")
        console.print()
    console.print("DOCKERFILE")
    console.print(f"  FROM {image.pinned_reference}")


def show_result(image: ResolvedImage) -> None:
    """Render the final selection as a sectioned panel with a Dockerfile line."""
    if _PLAIN:
        _show_result_plain(image)
        return

    blocks: list[RenderableType] = []
    for title, rows in _result_sections(image):
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="label", justify="left")
        grid.add_column(style="value")
        for label, value in rows:
            if label:
                grid.add_row(label, value)
            else:
                # Labelless rows (SELECTED) go in the first column so they line
                # up with the labels of the other sections.
                cell = value if isinstance(value, Text) else Text(str(value), style="value")
                grid.add_row(cell)
        blocks.append(Text(title, style="muted"))
        blocks.append(Padding(grid, (0, 0, 1, 2)))

    dockerfile = Syntax(
        f"FROM {image.pinned_reference}",
        "dockerfile",
        theme="ansi_dark",
        background_color="default",
    )
    blocks.append(Text("DOCKERFILE", style="muted"))
    blocks.append(Padding(dockerfile, (0, 0, 0, 2)))

    console.print(
        Panel(
            Group(*blocks),
            title="[ok]✓ resolved image",
            border_style="ok",
            padding=(1, 2),
        )
    )


def copy_to_clipboard(text: str) -> None:
    """Copy ``text`` to the system clipboard via the OSC 52 terminal escape."""
    payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
    sys.stdout.write(f"\033]52;c;{payload}\a")
    sys.stdout.flush()


def _read_key() -> str:
    """Read a single keypress without waiting for Enter.

    Falls back to line-based input when stdin is not an interactive terminal.
    """
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        return line.strip()[:1]
    try:
        import msvcrt  # type: ignore  # Windows
    except ImportError:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)  # type: ignore
        try:
            tty.setraw(fd)  # type: ignore
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)  # type: ignore
    else:
        return msvcrt.getwch()  # type: ignore


def result_actions(image: ResolvedImage) -> bool:
    """Show the post-result action menu.

    Reads a single keypress (no Enter required). Returns ``True`` if the user
    asked for a new selection, ``False`` to exit.
    """
    while True:
        console.print(
            "\n[muted]Actions:[/muted]  "
            "[accent]\\[f][/accent] Copy FROM line   "
            "[accent]\\[d][/accent] Copy digest   "
            "[accent]\\[n][/accent] New selection   "
            "[accent]\\[enter][/accent] exit"
        )
        console.print("[accent]›[/accent] ", end="")
        try:
            key = _read_key()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return False
        console.print(key)

        choice = key.lower()
        if choice in ("", "\r", "\n", "\x03", "\x04"):  # enter / ctrl-c / ctrl-d
            return False
        if choice == "f":
            copy_to_clipboard(f"FROM {image.pinned_reference}")
            console.print("[ok]✓ Copied FROM line to clipboard[/ok]")
            return False
        elif choice == "d":
            copy_to_clipboard(image.digest)
            console.print("[ok]✓ Copied digest to clipboard[/ok]")
            return False
        elif choice == "n":
            return True
        else:
            console.print(f"[warn]Unknown option: {choice}[/warn]")


def info(message: str) -> None:
    console.print(f"[muted]{message}[/muted]")


def error(message: str) -> None:
    console.print(f"[err]✗ {message}[/err]")


def cancelled() -> None:
    console.print("[warn]Cancelled.[/warn]")
