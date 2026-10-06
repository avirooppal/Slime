"""A self-contained terminal design preview with explicitly illustrative data."""

from io import StringIO
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.terminal_theme import TerminalTheme
from rich.text import Text

MINT = "#a3e8ba"
MUTED = "#8b9aab"
BORDER = "#344452"
INK = "#dfe7ed"
AMBER = "#efc078"
THEME = TerminalTheme(
    (13, 20, 26), (223, 231, 237),
    [(13, 20, 26), (234, 139, 139), (163, 232, 186), (239, 192, 120),
     (147, 185, 228), (190, 165, 221), (131, 209, 201), (223, 231, 237)],
)


def metric(label: str, value: str, detail: str, color: str = MINT) -> Panel:
    """Compact metric card with scope visible beside every number."""
    return Panel(
        Group(Text(label, style=MUTED), Text(value, style=f"bold {color}"),
              Text(detail, style=MUTED)),
        border_style=BORDER, box=box.ROUNDED, padding=(1, 2),
    )


def dashboard(width: int = 112) -> Group:
    """Build the illustrative overview without touching configuration or a database."""
    header = Table.grid(expand=True)
    header.add_column(ratio=1)
    header.add_column(justify="right")
    header.add_row(Text("SLIME / agent console", style=f"bold {MINT}"),
                   Text("PREVIEW  /  SAMPLE DATA", style=AMBER))
    header.add_row(Text("Local development   /   workspace: acme-api", style=MUTED),
                   Text("Snapshot 14:32:08", style=MUTED))

    summary = Panel(
        Group(Text("01 service needs attention", style=f"bold {AMBER}"),
              Text("Worker exited. Restart proposed; dry-run keeps execution paused.", style=INK)),
        border_style=BORDER, padding=(1, 2), box=box.ROUNDED,
    )
    cards = Table.grid(expand=True, padding=(0, 1))
    columns = 4 if width >= 100 else 2
    for _ in range(columns):
        cards.add_column(ratio=1)
    metrics = [metric("SERVICE HEALTH", "3 / 4", "latest observations"),
               metric("OPEN INCIDENTS", "01", "1 investigating", AMBER),
               metric("VERIFIED REPAIRS", "12 / 13", "stable / tried (24h)"),
               metric("MEDIAN RECOVERY", "2m 14s", "stable repairs (24h)")]
    for start in range(0, len(metrics), columns):
        cards.add_row(*metrics[start:start + columns])

    services = Table(expand=True, box=box.SIMPLE, border_style=BORDER,
                     header_style=MUTED, padding=(0, 1))
    for title in ("SERVICE", "HEALTH", "PROBE", "RESPONSE", "OBSERVED"):
        services.add_column(title)
    for name, health, probe, latency, age, color in [
        ("api", "Healthy", "HTTP /health", "42 ms", "2s ago", MINT),
        ("worker", "Exited", "Owned process", "--", "3s ago", AMBER),
        ("postgres", "Reachable", "TCP :5432", "4 ms", "2s ago", MINT),
        ("redis", "Reachable", "TCP :6379", "2 ms", "2s ago", MINT),
    ]:
        services.add_row(Text(name, style=f"bold {INK}"), Text(health, style=color),
                         Text(probe, style=MUTED), Text(latency, style=INK),
                         Text(age, style=MUTED))

    resources = Table.grid(expand=True, padding=(0, 1))
    resources.add_column(width=10)
    resources.add_column()
    resources.add_column(justify="right")
    for label, percentage in [("CPU", 18), ("Memory", 42), ("Disk", 61)]:
        filled = round(percentage / 5)
        bar = Text("=" * filled, style=MINT)
        bar.append("-" * (20 - filled), style=BORDER)
        resources.add_row(Text(label, style=MUTED), bar, Text(f"{percentage}%", style=INK))
    resources.add_row("", "", "")
    resources.add_row(Text("Agent", style=MUTED), Text("86 MB RSS", style=INK), "")
    resources.add_row(Text("Polling", style=MUTED), Text("Every 5 seconds", style=INK), "")

    controls = Table.grid(expand=True, padding=(0, 1))
    controls.add_column(style=MUTED)
    controls.add_column(justify="right")
    for label, value, color in [
        ("Execution", "DRY-RUN", AMBER),
        ("Circuit breaker", "Closed", MINT),
        ("Kill switch", "Off", MINT),
        ("Auto attempts / hour", "0 / 5", INK),
        ("Pending approvals", "0", INK),
        ("Diagnosis", "Local retrieval + runbooks", INK),
    ]:
        controls.add_row(label, Text(value, style=color))
    lower = Table.grid(expand=True, padding=(0, 1))
    lower.add_column(ratio=1)
    panels = [
        Panel(resources, title="Host resources", title_align="left", border_style=BORDER,
              padding=(1, 2)),
        Panel(controls, title="Agent controls", title_align="left", border_style=BORDER,
              padding=(1, 2)),
    ]
    if width >= 100:
        lower.add_column(ratio=1)
        lower.add_row(*panels)
    else:
        for panel in panels:
            lower.add_row(panel)

    activity = Table.grid(expand=True, padding=(0, 2))
    activity.add_column(width=9, style=MUTED)
    activity.add_column(width=11)
    activity.add_column(style=INK)
    for at, stage, message, color in [
        ("14:32:06", "PROPOSED", "Restart worker / confidence 0.96 / held by dry-run", AMBER),
        ("14:32:05", "DIAGNOSED", "Worker exit confirmed by owned process identity", INK),
        ("14:32:03", "DETECTED", "worker / process is no longer running", AMBER),
        ("14:18:41", "VERIFIED", "api / recovery stable for 120s / earlier live run", MINT),
    ]:
        activity.add_row(at, Text(stage, style=color), message)

    return Group(
        Text(""), header, Text(""), summary, cards, Text(""),
        Panel(services, title="Service inventory", title_align="left", border_style=BORDER),
        lower,
        Panel(activity, title="Recent activity", title_align="left", border_style=BORDER,
              padding=(1, 1)),
        Text("  DEMO SNAPSHOT  /  Illustrative metrics, not live telemetry.  /  No services started.",
             style=MUTED), Text(""),
    )


def show_preview(output: Path | None = None) -> None:
    """Render to the terminal and optionally export an HTML or SVG preview."""
    if output and output.suffix.lower() not in {".svg", ".html"}:
        raise ValueError("Preview output must end in .svg or .html")
    console = Console(
        record=True, width=112 if output else None, style=INK,
        file=StringIO() if output else None,
        force_terminal=True if output else None,
        legacy_windows=False if output else None,
    )
    console.print(dashboard(console.width))
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix.lower() == ".svg":
            console.save_svg(output, title="slime agent / console preview", theme=THEME)
        else:
            console.save_html(output, theme=THEME)
