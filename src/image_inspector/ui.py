"""Modern terminal UI: themed banner, arrow-key prompts, spinners, result panel."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pyfiglet
import questionary
from questionary import Choice, Separator, Style
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .models import Category, Language, ResolvedImage

_THEME = Theme(
    {
        "accent": "bold cyan",
        "muted": "grey58",
        "label": "bold white",
        "value": "bright_cyan",
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
    }
)

console = Console(theme=_THEME)

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
        ("disabled", "fg:#6b7280 italic"),
    ]
)


def banner() -> None:
    """Print the branded launch banner inside a bordered panel."""
    art = pyfiglet.figlet_format("image inspector", font="small")
    inner = Group(
        Align.center(Text(art.rstrip("\n"), style="accent")),
        Align.center(Text("pin official base images by digest", style="muted")),
    )
    console.print(Panel(inner, border_style="accent", padding=(1, 2)))


@contextmanager
def working(message: str) -> Iterator[None]:
    """Show an animated spinner while a block of work runs."""
    with console.status(f"[accent]{message}", spinner="dots"):
        yield


def _ask(message: str, choices: list) -> object | None:
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
        choices.append(Separator(f"── {heading} ──"))
        choices.extend(Choice(title=lang.label, value=lang) for lang in group)
    return _ask("Select a language or base image", choices)


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


def show_result(image: ResolvedImage) -> None:
    """Render the final selection as a panel with a copy-paste Dockerfile line."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="label", justify="right")
    table.add_column(style="value")
    table.add_row("Language", image.language.label)
    table.add_row("Image", image.reference)
    created = image.created.strftime("%Y-%m-%d %H:%M:%S %Z").strip() if image.created else "unknown"
    table.add_row("Created", created)
    table.add_row("Download", f"{format_size(image.size)} (compressed, linux/amd64)")
    table.add_row("Digest", image.digest)

    dockerfile = Syntax(
        f"FROM {image.pinned_reference}",
        "dockerfile",
        theme="ansi_dark",
        background_color="default",
    )

    body = Group(
        table,
        Text("\nDockerfile:", style="muted"),
        dockerfile,
    )
    console.print(
        Panel(
            body,
            title="[ok]✓ resolved image",
            border_style="ok",
            padding=(1, 2),
        )
    )


def info(message: str) -> None:
    console.print(f"[muted]{message}[/muted]")


def error(message: str) -> None:
    console.print(f"[err]✗ {message}[/err]")


def cancelled() -> None:
    console.print("[warn]Cancelled.[/warn]")
