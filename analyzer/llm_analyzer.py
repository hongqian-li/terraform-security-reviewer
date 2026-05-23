"""LLM-based analysis using the Claude API for complex security patterns."""

import anthropic

from analyzer.rule_checker import Finding

_SYSTEM_PROMPT = """\
You are a Terraform security expert. Analyze the provided Terraform code for:
- Security misconfigurations not caught by simple pattern matching
- GDPR-relevant data exposure risks
- Cost optimization issues
- Infrastructure best-practice violations

For each issue found, respond with a JSON array. Each element must have:
  rule_id, severity (CRITICAL|HIGH|MEDIUM|LOW|INFO), title, description, line (integer or null)

If no issues are found, return an empty array [].
Respond with raw JSON only — no markdown fences, no explanation.
"""


def analyze_with_llm(file_path: str, content: str, model: str = "claude-sonnet-4-6") -> list[Finding]:
    """Send a .tf file to Claude for deep analysis and return structured findings."""
    client = anthropic.Anthropic()

    user_message = f"File: {file_path}\n\n```hcl\n{content}\n```"

    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = message.content[0].text.strip()

    import json
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for item in items:
        findings.append(Finding(
            rule_id=item.get("rule_id", "LLM-000"),
            severity=item.get("severity", "INFO"),
            title=item.get("title", ""),
            description=item.get("description", ""),
            file=file_path,
            line=item.get("line"),
        ))
    return findings
