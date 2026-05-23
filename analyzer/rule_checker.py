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
# Public API
# ---------------------------------------------------------------------------

def check_file(file_path: Path, content: str) -> list[Finding]:
    """Run all rules against a single file and return combined findings."""
    findings = []
    for rule_fn in _RULES:
        findings.extend(rule_fn(file_path, content))
    return findings
