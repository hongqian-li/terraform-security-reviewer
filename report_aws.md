# Terraform Security Review Report

**Generated:** 2026-05-27 10:33 UTC
**Files scanned:** 1
**Total findings:** 10

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 3 |
| 🟠 HIGH | 4 |
| 🟡 MEDIUM | 2 |
| 🔵 LOW | 1 |
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

### 🔴 [CRITICAL] S3 bucket has no versioning — data loss on overwrite or delete `LLM-AWS-001`

**Location:** `tests\fixtures\sample_bad.tf:1`
**Description:** aws_s3_bucket 'my_bucket' has no versioning block. Combined with acl='public-read', any authenticated AWS user can overwrite or delete objects with no recovery path. Enable versioning and add a lifecycle rule to expire old versions after 90 days.

---

### 🟠 [HIGH] EBS volume not encrypted `EBS-001`

**Location:** `tests\fixtures\sample_bad.tf:6`
**Description:** aws_ebs_volume does not set `encrypted = true`. Data at rest is unencrypted.

---

### 🟠 [HIGH] Security group open to the world `SG-001`

**Location:** `tests\fixtures\sample_bad.tf:19`
**Description:** A security group rule allows ingress/egress from 0.0.0.0/0.

---

### 🟠 [HIGH] S3 bucket missing server-side encryption configuration `LLM-AWS-002`

**Location:** `tests\fixtures\sample_bad.tf:1`
**Description:** aws_s3_bucket 'my_bucket' has no aws_s3_bucket_server_side_encryption_configuration. Data at rest is stored unencrypted. Add SSE-S3 (AES256) at minimum, or SSE-KMS with a customer-managed key for compliance with PCI-DSS and HIPAA workloads.

---

### 🟠 [HIGH] RDS instance password hardcoded — rotation impossible without code change `LLM-AWS-003`

**Location:** `tests\fixtures\sample_bad.tf:25`
**Description:** aws_db_instance 'mydb' sets password as a string literal. Beyond the immediate secret-leak risk, hardcoded passwords cannot be rotated without a Terraform apply, creating a window of exposure. Use aws_secretsmanager_secret + aws_db_instance manage_master_user_password=true or source the value from SSM Parameter Store with a sensitive variable.

---

### 🟡 [MEDIUM] Security group allows all TCP ports — missing egress restriction `LLM-AWS-004`

**Location:** `tests\fixtures\sample_bad.tf:12`
**Description:** aws_security_group 'allow_all' opens ports 0-65535 inbound from 0.0.0.0/0 and has no egress block, which defaults to allow-all outbound. This enables both inbound exploitation and outbound data exfiltration. Restrict ingress to specific ports (443, 22 via bastion) and add an explicit egress rule limited to known destinations.

---

### 🟡 [MEDIUM] RDS instance missing deletion protection and backup retention `LLM-AWS-005`

**Location:** `tests\fixtures\sample_bad.tf:23`
**Description:** aws_db_instance 'mydb' does not set deletion_protection=true or backup_retention_period. A misconfigured destroy or accidental terraform apply could permanently delete the database with no automated backup to restore from. Set deletion_protection=true and backup_retention_period to at least 7.

---

### 🔵 [LOW] No resource tags — cost attribution and compliance tracking impossible `LLM-AWS-006`

**Location:** `tests\fixtures\sample_bad.tf`
**Description:** None of the four resources define a tags block. Without tags (Environment, Owner, CostCenter), AWS Cost Explorer cannot attribute spend, and compliance tools (AWS Config, Security Hub) cannot filter findings by team or workload. Add a default_tags block in the provider or explicit tags on each resource.

---

## Scanned Files

- `tests\fixtures\sample_bad.tf`
