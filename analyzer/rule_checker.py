"""Rule-based checks for common Terraform security misconfigurations."""

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    file: str
    line: int | None = None
    resource: str | None = None


# Each rule is a callable: (file_path, content) -> list[Finding]
_RULES: list = []


def rule(fn):
    _RULES.append(fn)
    return fn


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@rule
def check_public_s3_bucket(file_path: Path, content: str) -> list[Finding]:
    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        if re.search(r'acl\s*=\s*"public-read"', line) or re.search(r'acl\s*=\s*"public-read-write"', line):
            findings.append(Finding(
                rule_id="S3-001",
                severity="CRITICAL",
                title="S3 bucket with public ACL",
                description="Bucket ACL grants public read/write access. This exposes data to the internet.",
                file=str(file_path),
                line=i,
            ))
    return findings


@rule
def check_unencrypted_ebs(file_path: Path, content: str) -> list[Finding]:
    findings = []
    blocks = re.finditer(r'resource\s+"aws_ebs_volume"\s+"(\w+)"\s*\{([^}]*)\}', content, re.DOTALL)
    for block in blocks:
        resource_name = block.group(1)
        body = block.group(2)
        if not re.search(r'encrypted\s*=\s*true', body):
            line = content[: block.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="EBS-001",
                severity="HIGH",
                title="EBS volume not encrypted",
                description="aws_ebs_volume does not set `encrypted = true`. Data at rest is unencrypted.",
                file=str(file_path),
                line=line,
                resource=resource_name,
            ))
    return findings


@rule
def check_open_security_group(file_path: Path, content: str) -> list[Finding]:
    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', line):
            findings.append(Finding(
                rule_id="SG-001",
                severity="HIGH",
                title="Security group open to the world",
                description="A security group rule allows ingress/egress from 0.0.0.0/0.",
                file=str(file_path),
                line=i,
            ))
    return findings


@rule
def check_hardcoded_secrets(file_path: Path, content: str) -> list[Finding]:
    findings = []
    patterns = [
        (r'(?i)(password|secret|token|api_key)\s*=\s*"[^${\s][^"]{4,}"', "Hardcoded credential"),
    ]
    for i, line in enumerate(content.splitlines(), start=1):
        for pattern, label in patterns:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id="SEC-001",
                    severity="CRITICAL",
                    title=f"Hardcoded secret: {label}",
                    description="A credential appears to be hardcoded. Use variables or a secrets manager instead.",
                    file=str(file_path),
                    line=i,
                ))
    return findings


# ---------------------------------------------------------------------------
# Azure rules
# ---------------------------------------------------------------------------

@rule
def check_azure_public_blob_storage(file_path: Path, content: str) -> list[Finding]:
    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        if re.search(r'allow_nested_items_to_be_public\s*=\s*true', line):
            findings.append(Finding(
                rule_id="AZ-STG-001",
                severity="CRITICAL",
                title="Azure Storage Account allows public blob access",
                description=(
                    "`allow_nested_items_to_be_public = true` permits anonymous public read "
                    "access to blobs. Set it to false unless explicitly required."
                ),
                file=str(file_path),
                line=i,
            ))
    return findings


@rule
def check_azure_open_nsg(file_path: Path, content: str) -> list[Finding]:
    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        if re.search(r'source_address_prefix\s*=\s*"\*"', line):
            findings.append(Finding(
                rule_id="AZ-NSG-001",
                severity="HIGH",
                title="Azure NSG rule open to the internet",
                description=(
                    "`source_address_prefix = \"*\"` allows traffic from any IP address. "
                    "Restrict to known CIDRs or service tags."
                ),
                file=str(file_path),
                line=i,
            ))
    return findings


@rule
def check_azure_sql_public_access(file_path: Path, content: str) -> list[Finding]:
    findings = []
    blocks = re.finditer(
        r'resource\s+"azurerm_mssql_server"\s+"(\w+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        content, re.DOTALL,
    )
    for block in blocks:
        resource_name = block.group(1)
        body = block.group(2)
        line = content[: block.start()].count("\n") + 1
        if re.search(r'public_network_access_enabled\s*=\s*true', body):
            findings.append(Finding(
                rule_id="AZ-SQL-001",
                severity="HIGH",
                title="Azure SQL Server has public network access enabled",
                description=(
                    "`public_network_access_enabled = true` exposes the SQL server endpoint to the internet. "
                    "Use private endpoints instead."
                ),
                file=str(file_path),
                line=line,
                resource=resource_name,
            ))
        if re.search(r'minimum_tls_version\s*=\s*"Disabled"', body):
            findings.append(Finding(
                rule_id="AZ-SQL-002",
                severity="HIGH",
                title="Azure SQL Server has TLS disabled",
                description=(
                    "`minimum_tls_version = \"Disabled\"` allows unencrypted connections to the SQL server. "
                    "Set to \"1.2\" or higher."
                ),
                file=str(file_path),
                line=line,
                resource=resource_name,
            ))
    return findings


@rule
def check_azure_keyvault_purge_protection(file_path: Path, content: str) -> list[Finding]:
    findings = []
    blocks = re.finditer(
        r'resource\s+"azurerm_key_vault"\s+"(\w+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
        content, re.DOTALL,
    )
    for block in blocks:
        resource_name = block.group(1)
        body = block.group(2)
        if not re.search(r'purge_protection_enabled\s*=\s*true', body):
            line = content[: block.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="AZ-KV-001",
                severity="MEDIUM",
                title="Azure Key Vault purge protection not enabled",
                description=(
                    "`purge_protection_enabled` is not set to true. Without it, a deleted vault "
                    "and its secrets can be permanently purged immediately, risking data loss."
                ),
                file=str(file_path),
                line=line,
                resource=resource_name,
            ))
    return findings


@rule
def check_azure_app_service_https(file_path: Path, content: str) -> list[Finding]:
    findings = []
    app_resources = ("azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_app_service")
    pattern = r'resource\s+"(' + "|".join(app_resources) + r')"\s+"(\w+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    blocks = re.finditer(pattern, content, re.DOTALL)
    for block in blocks:
        resource_name = block.group(2)
        body = block.group(3)
        line = content[: block.start()].count("\n") + 1
        if re.search(r'https_only\s*=\s*false', body):
            findings.append(Finding(
                rule_id="AZ-APP-001",
                severity="MEDIUM",
                title="Azure App Service allows plain HTTP traffic",
                description=(
                    "`https_only = false` permits unencrypted HTTP connections. "
                    "Set `https_only = true` to enforce TLS."
                ),
                file=str(file_path),
                line=line,
                resource=resource_name,
            ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_file(file_path: Path, content: str) -> list[Finding]:
    """Run all rules against a single file and return combined findings."""
    findings = []
    for rule_fn in _RULES:
        findings.extend(rule_fn(file_path, content))
    return findings
