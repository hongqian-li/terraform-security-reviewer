# Terraform Security Review Report

**Generated:** 2026-05-27 10:34 UTC
**Files scanned:** 2
**Total findings:** 23

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 6 |
| 🟠 HIGH | 9 |
| 🟡 MEDIUM | 6 |
| 🔵 LOW | 2 |
| ⚪ INFO | 0 |

## Findings

### 🔴 [CRITICAL] S3 bucket with public ACL `S3-001`

**Location:** `tests\fixtures\sample_bad.tf:3`
**Description:** Bucket ACL grants public read/write access. This exposes data to the internet.

---

### 🔴 [CRITICAL] Hardcoded secret: Hardcoded credential `SEC-001`

**Location:** `tests\fixtures\sample_bad.tf:25`
**Description:** A credential appears to be hardcoded. Use variables or a secrets manager instead.

---

### 🔴 [CRITICAL] Hardcoded secret: Hardcoded credential `SEC-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:40`
**Description:** A credential appears to be hardcoded. Use variables or a secrets manager instead.

---

### 🔴 [CRITICAL] Azure Storage Account allows public blob access `AZ-STG-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:15`
**Description:** `allow_nested_items_to_be_public = true` permits anonymous public read access to blobs. Set it to false unless explicitly required.

---

### 🔴 [CRITICAL] S3 bucket has no versioning — data loss on overwrite or delete `LLM-AWS-001`

**Location:** `tests\fixtures\sample_bad.tf:1`
**Description:** aws_s3_bucket 'my_bucket' has no versioning block. Combined with acl='public-read', any authenticated AWS user can overwrite or delete objects with no recovery path. Enable versioning and add a lifecycle rule to expire old versions after 90 days.

---

### 🔴 [CRITICAL] SQL administrator password is hardcoded in plaintext `LLM-AZ-002`

**Location:** `tests\fixtures\sample_bad_azure.tf:40`
**Description:** The administrator_login_password for azurerm_mssql_server 'bad_sql' is a string literal. Credentials in source control are a persistent secret-leak risk even after rotation. Use a var with sensitive=true sourced from a secrets manager (e.g., Azure Key Vault reference or Terraform Cloud variable set).

---

### 🟠 [HIGH] EBS volume not encrypted `EBS-001`

**Location:** `tests\fixtures\sample_bad.tf:6`
**Description:** aws_ebs_volume does not set `encrypted = true`. Data at rest is unencrypted.

---

### 🟠 [HIGH] Security group open to the world `SG-001`

**Location:** `tests\fixtures\sample_bad.tf:19`
**Description:** A security group rule allows ingress/egress from 0.0.0.0/0.

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

### 🟠 [HIGH] S3 bucket missing server-side encryption configuration `LLM-AWS-002`

**Location:** `tests\fixtures\sample_bad.tf:1`
**Description:** aws_s3_bucket 'my_bucket' has no aws_s3_bucket_server_side_encryption_configuration. Data at rest is stored unencrypted. Add SSE-S3 (AES256) at minimum, or SSE-KMS with a customer-managed key for compliance with PCI-DSS and HIPAA workloads.

---

### 🟠 [HIGH] RDS instance password hardcoded — rotation impossible without code change `LLM-AWS-003`

**Location:** `tests\fixtures\sample_bad.tf:25`
**Description:** aws_db_instance 'mydb' sets password as a string literal. Beyond the immediate secret-leak risk, hardcoded passwords cannot be rotated without a Terraform apply, creating a window of exposure. Use aws_secretsmanager_secret + aws_db_instance manage_master_user_password=true or source the value from SSM Parameter Store with a sensitive variable.

---

### 🟠 [HIGH] Storage account lacks private endpoint — data exfiltration risk `LLM-AZ-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:7`
**Description:** azurerm_storage_account 'bad_storage' has no private_endpoint_connection and no network_rules block restricting access. Combined with allow_nested_items_to_be_public=true, any internet actor can read blob data. Add a network_rules block with default_action='Deny' and restrict to known virtual network subnets.

---

### 🟠 [HIGH] Key Vault purge protection disabled — secrets permanently deletable `LLM-AZ-003`

**Location:** `tests\fixtures\sample_bad_azure.tf:46`
**Description:** azurerm_key_vault 'bad_kv' does not set purge_protection_enabled=true. Without it, a privileged insider or compromised credential can purge vault contents within the 7-day soft-delete window with no recovery path. Enable purge_protection_enabled and extend soft_delete_retention_days to at least 30.

---

### 🟡 [MEDIUM] Azure Key Vault purge protection not enabled `AZ-KV-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:46`
**Description:** `purge_protection_enabled` is not set to true. Without it, a deleted vault and its secrets can be permanently purged immediately, risking data loss.

---

### 🟡 [MEDIUM] Azure App Service allows plain HTTP traffic `AZ-APP-001`

**Location:** `tests\fixtures\sample_bad_azure.tf:58`
**Description:** `https_only = false` permits unencrypted HTTP connections. Set `https_only = true` to enforce TLS.

---

### 🟡 [MEDIUM] Security group allows all TCP ports — missing egress restriction `LLM-AWS-004`

**Location:** `tests\fixtures\sample_bad.tf:12`
**Description:** aws_security_group 'allow_all' opens ports 0-65535 inbound from 0.0.0.0/0 and has no egress block, which defaults to allow-all outbound. This enables both inbound exploitation and outbound data exfiltration. Restrict ingress to specific ports (443, 22 via bastion) and add an explicit egress rule limited to known destinations.

---

### 🟡 [MEDIUM] RDS instance missing deletion protection and backup retention `LLM-AWS-005`

**Location:** `tests\fixtures\sample_bad.tf:23`
**Description:** aws_db_instance 'mydb' does not set deletion_protection=true or backup_retention_period. A misconfigured destroy or accidental terraform apply could permanently delete the database with no automated backup to restore from. Set deletion_protection=true and backup_retention_period to at least 7.

---

### 🟡 [MEDIUM] NSG rule allows all protocols — overly permissive blast radius `LLM-AZ-004`

**Location:** `tests\fixtures\sample_bad_azure.tf:19`
**Description:** azurerm_network_security_rule 'allow_all_inbound' uses protocol='*', source_port_range='*', destination_port_range='*', and source_address_prefix='*'. This exposes every port on every VM in the NSG to the public internet. Scope to specific protocols (TCP/UDP), ports (e.g. 443), and source CIDR ranges. Consider Azure Bastion for SSH/RDP instead of open NSG rules.

---

### 🟡 [MEDIUM] App Service missing client certificate enforcement `LLM-AZ-005`

**Location:** `tests\fixtures\sample_bad_azure.tf:58`
**Description:** azurerm_linux_web_app 'bad_app' sets https_only=false and has no client_certificate_mode. Beyond the obvious HTTP exposure, mutual TLS (mTLS) is missing, so any client can reach the app without authentication at the transport layer. Enable https_only=true and consider client_certificate_mode='Required' for internal APIs.

---

### 🔵 [LOW] No resource tags — cost attribution and compliance tracking impossible `LLM-AWS-006`

**Location:** `tests\fixtures\sample_bad.tf`
**Description:** None of the four resources define a tags block. Without tags (Environment, Owner, CostCenter), AWS Cost Explorer cannot attribute spend, and compliance tools (AWS Config, Security Hub) cannot filter findings by team or workload. Add a default_tags block in the provider or explicit tags on each resource.

---

### 🔵 [LOW] No diagnostic settings — audit trail absent for all resources `LLM-AZ-006`

**Location:** `tests\fixtures\sample_bad_azure.tf`
**Description:** None of the five resources configure azurerm_monitor_diagnostic_setting. Without audit logs forwarded to a Log Analytics workspace or Storage Account, there is no compliance trail for GDPR data-access or SOC 2 change-management controls. Add diagnostic settings to at minimum the storage account and SQL server.

---

## Scanned Files

- `tests\fixtures\sample_bad.tf`
- `tests\fixtures\sample_bad_azure.tf`
