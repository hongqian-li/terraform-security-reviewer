"""Generates a structured Markdown report from analysis findings."""

from pathlib import Path
from datetime import datetime

from analyzer.rule_checker import Finding

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def generate_report(findings: list[Finding], scanned_files: list[Path]) -> str:
    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        "# Terraform Security Review Report",
        f"\n**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Files scanned:** {len(scanned_files)}",
        f"**Total findings:** {len(findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, emoji in _SEVERITY_EMOJI.items():
        lines.append(f"| {emoji} {sev} | {counts.get(sev, 0)} |")

    lines += ["", "## Findings", ""]

    if not sorted_findings:
        lines.append("No issues found.")
    else:
        for f in sorted_findings:
            emoji = _SEVERITY_EMOJI.get(f.severity, "⚪")
            loc = f"{f.file}"
            if f.line:
                loc += f":{f.line}"
            lines += [
                f"### {emoji} [{f.severity}] {f.title} `{f.rule_id}`",
                "",
                f"**Location:** `{loc}`",
                f"**Description:** {f.description}",
                "",
                "---",
                "",
            ]

    lines += [
        "## Scanned Files",
        "",
    ]
    for p in scanned_files:
        lines.append(f"- `{p}`")

    return "\n".join(lines) + "\n"


def write_report(findings: list[Finding], scanned_files: list[Path], output_path: str) -> None:
    content = generate_report(findings, scanned_files)
    Path(output_path).write_text(content, encoding="utf-8")
