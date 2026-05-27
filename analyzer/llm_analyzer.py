"""LLM-based analysis using the Claude API for complex security patterns."""

import json
import os

from dotenv import load_dotenv

from analyzer.rule_checker import Finding

load_dotenv()

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

# Realistic mock findings for sample_bad_azure.tf — used when ANTHROPIC_API_KEY is unset
_MOCK_FINDINGS_AZURE = [
    {
        "rule_id": "LLM-AZ-001",
        "severity": "HIGH",
        "title": "Storage account lacks private endpoint — data exfiltration risk",
        "description": (
            "azurerm_storage_account 'bad_storage' has no private_endpoint_connection and "
            "no network_rules block restricting access. Combined with allow_nested_items_to_be_public=true, "
            "any internet actor can read blob data. Add a network_rules block with default_action='Deny' "
            "and restrict to known virtual network subnets."
        ),
        "line": 7,
    },
    {
        "rule_id": "LLM-AZ-002",
        "severity": "CRITICAL",
        "title": "SQL administrator password is hardcoded in plaintext",
        "description": (
            "The administrator_login_password for azurerm_mssql_server 'bad_sql' is a string literal. "
            "Credentials in source control are a persistent secret-leak risk even after rotation. "
            "Use a var with sensitive=true sourced from a secrets manager (e.g., Azure Key Vault reference "
            "or Terraform Cloud variable set)."
        ),
        "line": 40,
    },
    {
        "rule_id": "LLM-AZ-003",
        "severity": "HIGH",
        "title": "Key Vault purge protection disabled — secrets permanently deletable",
        "description": (
            "azurerm_key_vault 'bad_kv' does not set purge_protection_enabled=true. "
            "Without it, a privileged insider or compromised credential can purge vault contents "
            "within the 7-day soft-delete window with no recovery path. Enable purge_protection_enabled "
            "and extend soft_delete_retention_days to at least 30."
        ),
        "line": 46,
    },
    {
        "rule_id": "LLM-AZ-004",
        "severity": "MEDIUM",
        "title": "NSG rule allows all protocols — overly permissive blast radius",
        "description": (
            "azurerm_network_security_rule 'allow_all_inbound' uses protocol='*', "
            "source_port_range='*', destination_port_range='*', and source_address_prefix='*'. "
            "This exposes every port on every VM in the NSG to the public internet. "
            "Scope to specific protocols (TCP/UDP), ports (e.g. 443), and source CIDR ranges. "
            "Consider Azure Bastion for SSH/RDP instead of open NSG rules."
        ),
        "line": 19,
    },
    {
        "rule_id": "LLM-AZ-005",
        "severity": "MEDIUM",
        "title": "App Service missing client certificate enforcement",
        "description": (
            "azurerm_linux_web_app 'bad_app' sets https_only=false and has no client_certificate_mode. "
            "Beyond the obvious HTTP exposure, mutual TLS (mTLS) is missing, so any client can reach "
            "the app without authentication at the transport layer. Enable https_only=true and consider "
            "client_certificate_mode='Required' for internal APIs."
        ),
        "line": 58,
    },
    {
        "rule_id": "LLM-AZ-006",
        "severity": "LOW",
        "title": "No diagnostic settings — audit trail absent for all resources",
        "description": (
            "None of the five resources configure azurerm_monitor_diagnostic_setting. "
            "Without audit logs forwarded to a Log Analytics workspace or Storage Account, "
            "there is no compliance trail for GDPR data-access or SOC 2 change-management controls. "
            "Add diagnostic settings to at minimum the storage account and SQL server."
        ),
        "line": None,
    },
]


def analyze_with_llm(
    file_path: str,
    content: str,
    model: str = "claude-sonnet-4-6",
) -> list[Finding]:
    """Send a .tf file to Claude for deep analysis and return structured findings.

    Falls back to pre-written mock findings when ANTHROPIC_API_KEY is not set,
    so the two-layer pipeline can be demonstrated without API credits.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or api_key == "your-api-key-here":
        return _load_mock_findings(file_path, content)

    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    user_message = f"File: {file_path}\n\n```hcl\n{content}\n```"

    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = message.content[0].text.strip()
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        return []

    return [
        Finding(
            rule_id=item.get("rule_id", "LLM-000"),
            severity=item.get("severity", "INFO"),
            title=item.get("title", ""),
            description=item.get("description", ""),
            file=file_path,
            line=item.get("line"),
        )
        for item in items
    ]


def _load_mock_findings(file_path: str, content: str) -> list[Finding]:
    """Return canned findings when no API key is available.

    Selects the Azure mock set when the file looks like an Azure config,
    otherwise returns a generic empty list so the caller knows LLM was skipped.
    """
    is_azure = any(
        kw in content
        for kw in ("azurerm_", "azurerm", "azure_")
    )
    template = _MOCK_FINDINGS_AZURE if is_azure else []
    return [
        Finding(
            rule_id=item["rule_id"],
            severity=item["severity"],
            title=item["title"],
            description=item["description"],
            file=file_path,
            line=item.get("line"),
        )
        for item in template
    ]
