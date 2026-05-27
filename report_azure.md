# Terraform Security Review Report

**Generated:** 2026-05-23 11:53 UTC
**Files scanned:** 1
**Total findings:** 7

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 2 |
| 🔵 LOW | 0 |
| ⚪ INFO | 0 |

## Findings

### 🔴 [CRITICAL] Hardcoded secret: Hardcoded credential `SEC-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:40`
**Description:** A credential appears to be hardcoded. Use variables or a secrets manager instead.

---

### 🔴 [CRITICAL] Azure Storage Account allows public blob access `AZ-STG-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:15`
**Description:** `allow_nested_items_to_be_public = true` permits anonymous public read access to blobs. Set it to false unless explicitly required.

---

### 🟠 [HIGH] Azure NSG rule open to the internet `AZ-NSG-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:27`
**Description:** `source_address_prefix = "*"` allows traffic from any IP address. Restrict to known CIDRs or service tags.

---

### 🟠 [HIGH] Azure SQL Server has public network access enabled `AZ-SQL-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:34`
**Description:** `public_network_access_enabled = true` exposes the SQL server endpoint to the internet. Use private endpoints instead.

---

### 🟠 [HIGH] Azure SQL Server has TLS disabled `AZ-SQL-002`

**Location:** `tests\fixtures\sample_bad_azure.tf:34`
**Description:** `minimum_tls_version = "Disabled"` allows unencrypted connections to the SQL server. Set to "1.2" or higher.

---

### 🟡 [MEDIUM] Azure Key Vault purge protection not enabled `AZ-KV-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:46`
**Description:** `purge_protection_enabled` is not set to true. Without it, a deleted vault and its secrets can be permanently purged immediately, risking data loss.

---

### 🟡 [MEDIUM] Azure App Service allows plain HTTP traffic `AZ-APP-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:58`
**Description:** `https_only = false` permits unencrypted HTTP connections. Set `https_only = true` to enforce TLS.

---

## Scanned Files

- `tests\fixtures\sample_bad_azure.tf`
