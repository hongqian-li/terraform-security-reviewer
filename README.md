# terraform-security-reviewer

An AI-powered CLI tool for static analysis of Terraform infrastructure code. Combines rule-based detection with LLM analysis (Claude API) to identify security misconfigurations, GDPR-relevant exposures, and cost optimization opportunities. Outputs structured Markdown reports.

> Designed around a finding from my bachelor's thesis: deterministic, rule-based detection is more reliable than LLM-only approaches for compliance-critical use cases. The LLM layer acts as a second pass for complex patterns that rules can't catch.

## Features

- Recursive `.tf` file discovery from any directory
- Rule-based detection for common misconfigurations (AWS + Azure)
- Optional LLM-powered deep analysis via Claude API (`--llm` flag)
- Structured Markdown report output (`--output` flag)
- Non-zero exit code on CRITICAL/HIGH findings — CI/CD friendly
- GitHub Actions integration (planned)

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

## Tech Stack

Python, Click, Rich, Anthropic Claude API

## Installation

```bash
git clone https://github.com/hongqian-li/terraform-security-reviewer
cd terraform-security-reviewer
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt  # Windows
# or: .venv/bin/pip install -r requirements.txt  (Mac/Linux)
```

## Usage

```bash
# Scan a directory (rule-based only)
python main.py --path ./infra

# Scan a single file
python main.py --path ./infra/main.tf

# Also run Claude LLM analysis (requires ANTHROPIC_API_KEY)
python main.py --path ./infra --llm

# Save a Markdown report
python main.py --path ./infra --output report.md

# Choose a different Claude model
python main.py --path ./infra --llm --model claude-opus-4-6
```

## Project Structure

```
terraform-security-reviewer/
├── main.py                        # CLI entry point
├── requirements.txt
├── analyzer/
│   ├── file_reader.py             # Recursive .tf file discovery
│   ├── rule_checker.py            # Deterministic rule-based checks
│   └── llm_analyzer.py           # Claude API deep analysis
├── reports/
│   └── markdown_reporter.py      # Markdown report generation
└── tests/
    └── fixtures/
        ├── sample_bad.tf          # AWS bad example
        └── sample_bad_azure.tf    # Azure bad example
```

## Status

In active development. Rule-based detection and CLI are functional. LLM layer is wired and ready — requires `ANTHROPIC_API_KEY`.

## Author

Hongqian Li — [github.com/hongqian-li](https://github.com/hongqian-li)
