# terraform-security-reviewer

An AI-powered CLI tool for static analysis of Terraform infrastructure code. Combines rule-based detection with LLM analysis (Claude API) to identify security misconfigurations, GDPR-relevant exposures, and cost optimization opportunities. Outputs structured Markdown reports.

## Features

- Rule-based detection for common Terraform misconfigurations
- LLM-powered analysis via Claude API for complex security patterns
- GDPR-relevant exposure detection
- Cost optimization recommendations
- Markdown report generation
- GitHub Actions integration

## Tech Stack

Python, Click, Claude API, Terraform

## Usage

```bash
pip install terraform-security-reviewer
tf-review --path ./infra
```

## Status

🚧 In development

## Author

Hongqian Li — github.com/hongqian-li
