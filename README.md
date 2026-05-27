# terraform-security-reviewer

An AI-powered CLI tool for static analysis of Terraform infrastructure code. Combines rule-based detection with LLM analysis (Claude API) to identify security misconfigurations, GDPR-relevant exposures, and cost optimization opportunities. Outputs structured Markdown reports.

> Designed around a finding from my bachelor's thesis: deterministic, rule-based detection is more reliable than LLM-only approaches for compliance-critical use cases. The LLM layer acts as a second pass for complex patterns that rules can't catch.

## Features

- Recursive `.tf` file discovery from any directory
- Rule-based detection for common misconfigurations (AWS + Azure)
- Optional LLM-powered deep analysis via Claude API (`--llm` flag)
- Mock LLM mode for offline testing — no API key required
- Structured Markdown report output (`--output` flag)
- Non-zero exit code on CRITICAL/HIGH findings — CI/CD friendly

## Two-layer detection

The tool runs two passes over each file:

**Layer 1 — Rule-based (always on):** Fast regex/AST checks for known bad patterns. Deterministic, CI-safe, zero API cost. Examples: public S3 ACL, hardcoded secrets, open security groups.

**Layer 2 — LLM analysis (`--llm`):** Claude reasons over the full file to catch issues that require context across multiple attributes or resources — things regex can't see:

| What the LLM adds | Example |
|---|---|
| Multi-attribute reasoning | S3 bucket is public *and* has no `network_rules` — combined exfiltration path |
| Missing resource relationships | No `azurerm_monitor_diagnostic_setting` across any resource — compliance trail absent |
| Escalated remediation advice | Hardcoded password flagged by rules, but LLM explains why rotation is blocked without a code change |
| Implicit misconfigurations | RDS missing `deletion_protection` and `backup_retention_period` — no rule covers their absence |

On the Azure fixture, rule-based finds **7 issues**; adding `--llm` raises the total to **13**.  
On the AWS fixture: **4** rule-based → **10** with LLM.  
See [`report_both.md`](report_both.md) for a combined directory scan across both fixtures.

## Rules implemented

| Rule | Cloud | Severity | Description |
|------|-------|----------|-------------|
| `S3-001` | AWS | CRITICAL | S3 bucket with public ACL |
| `SEC-001` | Any | CRITICAL | Hardcoded passwords, tokens, or secrets |
| `EBS-001` | AWS | HIGH | EBS volume without encryption |
| `SG-001` | AWS | HIGH | Security group open to 0.0.0.0/0 |
| `AZ-STG-001` | Azure | CRITICAL | Storage account with public blob access |
| `AZ-NSG-001` | Azure | HIGH | NSG rule open to the internet (`*`) |
| `AZ-SQL-001` | Azure | HIGH | SQL Server with public network access enabled |
| `AZ-SQL-002` | Azure | HIGH | SQL Server with TLS disabled |
| `AZ-KV-001` | Azure | MEDIUM | Key Vault without purge protection |
| `AZ-APP-001` | Azure | MEDIUM | App Service allowing plain HTTP |

## Tech stack

Python, Click, Rich, Anthropic Claude API, python-dotenv

## Installation

```bash
git clone https://github.com/hongqian-li/terraform-security-reviewer
cd terraform-security-reviewer
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt  # Windows
# or: .venv/bin/pip install -r requirements.txt  (Mac/Linux)
```

## Configuration

To use the LLM layer with a real Claude API call, create a `.env` file in the project root:

```
ANTHROPIC_API_KEY=sk-ant-...
```

The `.env` file is gitignored. Without a key (or with the placeholder), `--llm` automatically falls back to pre-written mock findings so the full two-layer pipeline can be demonstrated offline.

## Usage

```bash
# Scan a directory (rule-based only)
python main.py --path ./infra

# Scan a single file
python main.py --path ./infra/main.tf

# Also run LLM analysis (uses mock findings if no API key is set)
python main.py --path ./infra --llm

# Save a Markdown report
python main.py --path ./infra --llm --output report.md

# Choose a different Claude model
python main.py --path ./infra --llm --model claude-opus-4-7
```

## Project structure

```
terraform-security-reviewer/
├── main.py                        # CLI entry point
├── requirements.txt
├── .env                           # API key (gitignored)
├── analyzer/
│   ├── file_reader.py             # Recursive .tf file discovery
│   ├── rule_checker.py            # Deterministic rule-based checks
│   └── llm_analyzer.py           # Claude API deep analysis + mock mode
├── reports/
│   └── markdown_reporter.py      # Markdown report generation
└── tests/
    └── fixtures/
        ├── sample_bad.tf          # AWS bad example
        └── sample_bad_azure.tf    # Azure bad example
```

## Author

Hongqian Li — [github.com/hongqian-li](https://github.com/hongqian-li)
