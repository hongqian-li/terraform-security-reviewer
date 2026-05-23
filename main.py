"""terraform-security-reviewer — CLI entry point."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from analyzer.file_reader import read_tf_files
from analyzer.rule_checker import check_file, Finding
from reports.markdown_reporter import write_report

console = Console()

_SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
}


@click.command()
@click.option(
    "--path", "-p",
    required=True,
    help="Path to a .tf file or directory to scan.",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Write a Markdown report to this file (optional).",
)
@click.option(
    "--llm/--no-llm",
    default=False,
    help="Also run Claude LLM analysis (requires ANTHROPIC_API_KEY).",
)
@click.option(
    "--model",
    default="claude-sonnet-4-6",
    show_default=True,
    help="Claude model to use for LLM analysis.",
)
def main(path: str, output: str | None, llm: bool, model: str) -> None:
    """Analyze Terraform files for security issues, cost risks, and best-practice violations."""

    # --- Discover and read files ---
    try:
        tf_files = read_tf_files(path)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)
    except PermissionError as exc:
        console.print(f"[bold red]Permission error:[/] {exc}")
        sys.exit(1)

    if not tf_files:
        console.print("[yellow]No .tf files found at the given path.[/]")
        sys.exit(0)

    console.print(f"\n[bold]terraform-security-reviewer[/]")
    console.print(f"Found [cyan]{len(tf_files)}[/] .tf file(s) under [cyan]{path}[/]:")
    for name in tf_files:
        console.print(f"  [dim]{name}[/]")
    console.print()

    # --- Rule-based analysis ---
    all_findings: list[Finding] = []
    for file_path, content in tf_files.items():
        findings = check_file(Path(file_path), content)
        all_findings.extend(findings)

    # --- Optional LLM analysis ---
    if llm:
        from analyzer.llm_analyzer import analyze_with_llm
        console.print("[dim]Running LLM analysis via Claude API…[/]")
        for file_path, content in tf_files.items():
            llm_findings = analyze_with_llm(file_path, content, model=model)
            all_findings.extend(llm_findings)

    # --- Display results ---
    _print_findings(all_findings, list(tf_files.keys()))

    # --- Optional report ---
    if output:
        write_report(all_findings, [Path(p) for p in tf_files], output)
        console.print(f"\n[green]Report written to:[/] {output}")

    # Exit with non-zero code if any critical/high findings
    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(1)


def _print_findings(findings: list[Finding], scanned_files: list[str]) -> None:
    if not findings:
        console.print("[bold green]No issues found.[/] Your Terraform looks clean.\n")
        return

    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=10)
    table.add_column("Title")
    table.add_column("Location")

    _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: _ORDER.get(f.severity, 99))

    for f in sorted_findings:
        color = _SEVERITY_COLOR.get(f.severity, "white")
        loc = Path(f.file).name
        if f.line:
            loc += f":{f.line}"
        table.add_row(
            f"[{color}]{f.severity}[/]",
            f.rule_id,
            f.title,
            loc,
        )

    console.print(table)
    console.print(f"[bold]{len(findings)}[/] finding(s) across [bold]{len(scanned_files)}[/] file(s).\n")


if __name__ == "__main__":
    main()
