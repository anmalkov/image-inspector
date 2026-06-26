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
from .models import Category, Language, ResolvedImage, ScanSource
from .report import ImageVulnerabilities, ReportSource

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


def format_update_notice(installed_version: str, latest_version: str | None) -> Text | None:
    """Build the light "a new version is available" line, or ``None`` if up to date.

    Used when the report itself is fine but PyPI advertises a newer tool release.
    """
    if not _is_newer(latest_version, installed_version):
        return None
    notice = Text()
    notice.append("⬆ ", style="accent")
    notice.append("A new version ", style="warn")
    notice.append(f"v{latest_version}", style="accent")
    notice.append(f" is available (you have v{installed_version}). Update with:\n", style="warn")
    notice.append(f"  {upgrade_command()}", style="value")
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
    warning.append("⚠ Using the bundled, outdated vulnerability report", style="warn")
    warning.append(f" (generated {format_date(generated_at)}).\n", style="warn")
    warning.append(
        f"  Your installed {_DISTRIBUTION_NAME} v{installed_version} is older than the "
        "published vulnerability data.\n",
        style="warn",
    )
    if _is_newer(latest_version, installed_version):
        warning.append(f"  A newer version (v{latest_version}) is available — update with:\n")
        warning.append(f"    {upgrade_command()}", style="value")
    else:
        warning.append("  A new version will be available soon.")
    return warning


def show_version_status(
    report_source: ReportSource | None,
    generated_at: datetime | None,
    installed_version: str,
    latest_version: str | None,
) -> None:
    """Print the outdated-report warning or the lighter update notice, if either applies.

    An ``OUTDATED`` report always takes precedence (its data is stale); otherwise a newer
    PyPI release surfaces the light update notice. Prints nothing when fully up to date.
    """
    if report_source is ReportSource.OUTDATED:
        console.print(format_outdated_warning(generated_at, installed_version, latest_version))
        return
    notice = format_update_notice(installed_version, latest_version)
    if notice is not None:
        console.print(notice)


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
        "vulnerabilities": None
        if vulns is None
        else {
            "critical": vulns.critical,
            "high": vulns.high,
            "medium": vulns.medium,
            "low": vulns.low,
            "unknown": vulns.unknown,
            "total": vulns.total,
            "scanned_at": vulns.scanned_at.isoformat() if vulns.scanned_at else None,
        },
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
            if label:
                console.print(f"  {label.ljust(width)}  {text}")
            else:
                console.print(f"  {text}")
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
