"""Rich terminal formatting for OpenCryptoDetect CLI."""


from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.version import __version__

console = Console()


def format_size(size_bytes: int) -> str:
    """Format bytes into human-readable size string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def render_banner() -> None:
    """Render tool header banner."""
    console.print(f"[bold cyan]OpenCryptoDetect[/bold cyan] [green]v{__version__}[/green]\n")


def render_inspection(ctx: AnalysisContext) -> None:
    """Render inspection-only result."""
    render_banner()
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold white")
    table.add_column("Value", style="cyan")

    table.add_row("File:", ctx.file_path.name)
    table.add_row("Path:", str(ctx.file_path.resolve()))
    table.add_row("SHA-256:", ctx.file_sha256)
    table.add_row("Size:", format_size(ctx.file_size_bytes))
    table.add_row("Format:", ctx.file_format)
    table.add_row("Architecture:", ctx.architecture.upper())
    table.add_row("Endianness:", ctx.endianness)
    if ctx.entry_point is not None:
        table.add_row("Entry point:", f"0x{ctx.entry_point:x}")

    console.print(Panel(table, title="[bold]Firmware Inspection[/bold]", border_style="blue"))


def render_analysis(
    ctx: AnalysisContext,
    json_path: str | None = None,
    cbom_path: str | None = None,
    html_path: str | None = None,
) -> None:
    """Render full analysis summary matching specification."""
    render_banner()

    # Firmware section
    console.print("[bold]Firmware[/bold]")
    console.print("─" * 40)
    console.print(f"File:          {ctx.file_path.name}")
    console.print(f"SHA-256:       {ctx.file_sha256}")
    console.print(f"Size:          {format_size(ctx.file_size_bytes)}")
    console.print(f"Architecture:  {ctx.architecture.upper()} ({ctx.bitness}-bit, {ctx.endianness})\n")

    # Analysis section
    console.print("[bold]Analysis[/bold]")
    console.print("─" * 40)
    console.print(f"Functions:     {len(ctx.functions)}")
    console.print(f"Analyzed:      {len(ctx.functions)}")
    console.print(f"Duration:      {ctx.timing.total_seconds:.3f}s\n")

    # Cryptographic primitives
    console.print("[bold]Cryptographic primitives[/bold]")
    console.print("─" * 40)
    if not ctx.findings:
        console.print("[italic yellow]No cryptographic primitives detected.[/italic yellow]\n")
    else:
        table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
        table.add_column("Algorithm")
        table.add_column("Location")
        table.add_column("Confidence")
        table.add_column("Methods")

        for f in ctx.findings:
            loc_str = f"0x{f.address:x}" if f.address else f.function_name
            conf_str = f"{f.confidence:.2f}"
            methods_str = ",".join(f.detection_methods)
            table.add_row(f.algorithm, loc_str, conf_str, methods_str)
        console.print(table)
        console.print()

    # Weak algorithms
    weak_findings = [f for f in ctx.findings if f.security_status in ("weak", "deprecated", "insecure")]
    if weak_findings:
        console.print("[bold red]Potential weak algorithms[/bold red]")
        console.print("─" * 40)
        for wf in weak_findings:
            loc_str = f"0x{wf.address:x}" if wf.address else wf.function_name
            console.print(f"[bold yellow]{wf.algorithm:<14}[/bold yellow] {loc_str:<12} [red]WARNING[/red] ({wf.security_note or 'Deprecated for secure applications'})")
        console.print()

    # Library candidates
    if ctx.library_candidates:
        console.print("[bold]Library candidates[/bold]")
        console.print("─" * 40)
        for lib in ctx.library_candidates:
            console.print(f"{lib.library_name:<16} Confidence: {lib.confidence:.2f} ({', '.join(lib.evidence[:2])})")
        console.print()

    # Detailed evidence section
    if ctx.findings:
        console.print("[bold]Evidence[/bold]")
        console.print("─" * 40)
        for f in ctx.findings:
            console.print(f"[bold cyan]{f.algorithm}[/bold cyan] at 0x{f.address:x}:")
            for ev in f.evidence:
                console.print(f"  • {ev}")
        console.print()

    # Reports section
    if json_path or cbom_path or html_path:
        console.print("[bold]Reports[/bold]")
        console.print("─" * 40)
        if json_path:
            console.print(f"JSON: {json_path}")
        if cbom_path:
            console.print(f"CBOM: {cbom_path}")
        if html_path:
            console.print(f"HTML: {html_path}")
        console.print()
