"""Generate the demo JSON datasets in data/.

Output is fully deterministic: every timestamp is derived from
config.REFERENCE_TIME and all randomness comes from a seeded generator, so
running this script twice produces byte-identical files. The system clock is
never consulted.

Usage:
    python -m data.generate_demo_data
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config  # noqa: E402

REF = config.REFERENCE_TIME
NAIROBI = ZoneInfo("Africa/Nairobi")
LONDON = ZoneInfo("Europe/London")
BERLIN = ZoneInfo("Europe/Berlin")

ORG = "org-001"
ORG2 = "org-002"


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def days_ago(days: float, hour: int = 9, minute: int = 0) -> str:
    """Timestamp `days` before the reference date at a fixed UTC time of day."""
    base = (REF - timedelta(days=days)).replace(hour=hour, minute=minute, second=0, microsecond=0)
    return iso(base)


def at(text: str) -> datetime:
    """Parse a fixed UTC scenario time like '2026-11-04T23:40:00Z'."""
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------

ORGANIZATIONS = [
    {
        "organization_id": ORG,
        "name": "Savanna Ridge Financial Ltd",
        "industry": "Financial services (digital lending)",
        "headquarters": "Nairobi, Kenya",
        "employee_count": 240,
        "cloud_provider": "AWS",
        "aws_account_ids": ["111122223333", "444455556666"],
        "primary_region": "af-south-1",
        "timezone": "Africa/Nairobi",
    },
    {
        "organization_id": ORG2,
        "name": "Kilima Highlands Coffee Cooperative",
        "industry": "Agriculture (cooperative)",
        "headquarters": "Nyeri, Kenya",
        "employee_count": 18,
        "cloud_provider": "AWS",
        "aws_account_ids": ["777788889999"],
        "primary_region": "af-south-1",
        "timezone": "Africa/Nairobi",
    },
]

# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def asset(asset_id, name, asset_type, service, exposure, sensitivity, criticality, controls, description,
          owner, environment="production", region="af-south-1", discovered_days=300, tags=(), org=ORG):
    return {
        "asset_id": asset_id,
        "organization_id": org,
        "name": name,
        "asset_type": asset_type,
        "service": service,
        "region": region,
        "environment": environment,
        "exposure": exposure,
        "data_sensitivity": sensitivity,
        "business_criticality": criticality,
        "owner": owner,
        "description": description,
        "discovered_at": days_ago(discovered_days, 7, 30),
        "security_controls": controls,
        "tags": list(tags),
    }


ASSETS = [
    # --- S3 ---
    asset("a-s3-001", "srf-customer-kyc-documents", "s3_bucket", "S3", "public", "pii", "critical",
          {"encryption_at_rest": False, "encryption_in_transit": True, "logging_enabled": False,
           "network_restricted": False, "backup_enabled": True},
          "Scanned national ID cards, payslips and selfies collected during loan onboarding.",
          "onboarding-team", discovered_days=410, tags=["kyc", "customer-data"]),
    asset("a-s3-002", "srf-marketing-website", "s3_bucket", "S3", "public", "public", "low",
          {"encryption_at_rest": True, "encryption_in_transit": True, "logging_enabled": True,
           "backup_enabled": False},
          "Static assets for the public marketing website (intentionally public).",
          "marketing", discovered_days=380, tags=["website"]),
    asset("a-s3-003", "srf-finance-reports-archive", "s3_bucket", "S3", "internal", "financial", "high",
          {"encryption_at_rest": False, "encryption_in_transit": True, "logging_enabled": True,
           "least_privilege": False, "backup_enabled": True},
          "Monthly management accounts, loan book exports and audit working papers.",
          "finance", discovered_days=350, tags=["finance"]),
    asset("a-s3-004", "srf-application-logs", "s3_bucket", "S3", "internal", "internal", "medium",
          {"encryption_at_rest": True, "encryption_in_transit": True, "logging_enabled": True,
           "least_privilege": True},
          "Application and load balancer logs.", "platform", discovered_days=330, tags=["logs"]),
    asset("a-s3-005", "srf-cloudtrail-logs", "s3_bucket", "S3", "internal", "internal", "high",
          {"encryption_at_rest": True, "encryption_in_transit": True, "logging_enabled": True,
           "least_privilege": True, "network_restricted": True, "key_rotation": True},
          "Organization CloudTrail log archive (object lock enabled).", "security", discovered_days=400,
          tags=["audit"]),
    # --- IAM ---
    asset("a-iam-001", "ops-admin", "iam_user", "IAM", "public", "internal", "critical",
          {"mfa_enforced": False, "least_privilege": False, "key_rotation": False, "logging_enabled": True},
          "Legacy shared administrator IAM user with console password (AdministratorAccess).",
          "platform", region="global", discovered_days=420, tags=["privileged", "legacy"]),
    asset("a-iam-002", "ci-deploy-role", "iam_role", "IAM", "internal", "internal", "high",
          {"least_privilege": False, "logging_enabled": True},
          "Role assumed by the CI pipeline to deploy workloads.", "platform", region="global",
          discovered_days=300, tags=["ci", "privileged"]),
    asset("a-iam-003", "svc-payments", "iam_user", "IAM", "internal", "financial", "critical",
          {"key_rotation": False, "least_privilege": True, "logging_enabled": True},
          "Programmatic IAM user used by the payments integration.", "payments", region="global",
          discovered_days=415, tags=["service-account"]),
    asset("a-iam-004", "security-audit-role", "iam_role", "IAM", "internal", "internal", "medium",
          {"mfa_enforced": True, "least_privilege": True, "logging_enabled": True},
          "Read-only role used by the security team for audits.", "security", region="global",
          discovered_days=260, tags=["audit"]),
    asset("a-iam-005", "platform-admin-sso", "sso_permission_set", "IAM", "internal", "internal",
          "critical",
          {"mfa_enforced": True, "least_privilege": True, "logging_enabled": True},
          "IAM Identity Center permission set for platform administrators (MFA enforced).",
          "platform", region="global", discovered_days=200, tags=["privileged", "sso"]),
    # --- EC2 ---
    asset("a-ec2-001", "bastion-01", "ec2_instance", "EC2", "public", "internal", "high",
          {"encryption_at_rest": True, "network_restricted": False, "mfa_enforced": False,
           "logging_enabled": True},
          "SSH bastion host for production access.", "platform", discovered_days=390,
          tags=["bastion"]),
    asset("a-ec2-002", "web-frontend-01", "ec2_instance", "EC2", "public", "internal", "high",
          {"encryption_at_rest": True, "network_restricted": True, "logging_enabled": True,
           "backup_enabled": True},
          "Customer-facing web front end behind HTTPS only.", "web-team", discovered_days=360,
          tags=["web"]),
    asset("a-ec2-003", "batch-worker-01", "ec2_instance", "EC2", "internal", "internal", "medium",
          {"encryption_at_rest": True, "network_restricted": True, "logging_enabled": True,
           "least_privilege": True},
          "Private subnet worker that runs credit scoring batch jobs.", "data-team", discovered_days=280,
          tags=["batch"]),
    asset("a-ec2-004", "legacy-reporting-01", "ec2_instance", "EC2", "public", "financial", "medium",
          {"encryption_at_rest": False, "network_restricted": False, "logging_enabled": False,
           "backup_enabled": False},
          "Forgotten Windows Server 2012 reporting box holding ledger extracts.", "finance",
          discovered_days=60, tags=["legacy", "shadow-it"]),
    # --- RDS ---
    asset("a-rds-001", "srf-customer-db", "rds_instance", "RDS", "public", "pii", "critical",
          {"encryption_at_rest": True, "encryption_in_transit": True, "network_restricted": False,
           "backup_enabled": True, "logging_enabled": True},
          "PostgreSQL database with customer profiles, contact details and loan balances.",
          "core-banking", discovered_days=420, tags=["customer-data"]),
    asset("a-rds-002", "srf-payments-ledger", "rds_instance", "RDS", "internal", "financial", "critical",
          {"encryption_at_rest": True, "encryption_in_transit": True, "network_restricted": True,
           "backup_enabled": True, "logging_enabled": True, "key_rotation": True},
          "Payments ledger (disbursements and repayments).", "payments", discovered_days=420,
          tags=["payments"]),
    asset("a-rds-003", "srf-analytics-replica", "rds_instance", "RDS", "internal", "pii", "medium",
          {"encryption_at_rest": False, "backup_enabled": False, "network_restricted": True},
          "Staging analytics copy of the customer database, refreshed ad hoc.", "data-team",
          environment="staging", discovered_days=150, tags=["analytics"]),
    # --- KMS ---
    asset("a-kms-001", "customer-data-key", "kms_key", "KMS", "internal", "internal", "critical",
          {"key_rotation": False, "least_privilege": False, "logging_enabled": True},
          "Customer-managed key protecting customer data stores.", "security", discovered_days=400,
          tags=["encryption"]),
    asset("a-kms-002", "payments-key", "kms_key", "KMS", "internal", "internal", "critical",
          {"key_rotation": True, "least_privilege": True, "logging_enabled": True},
          "Customer-managed key for the payments ledger.", "security", discovered_days=400,
          tags=["encryption", "payments"]),
    # --- Lambda ---
    asset("a-lambda-001", "payment-webhook-handler", "lambda_function", "Lambda", "public", "financial",
          "high",
          {"network_restricted": False, "least_privilege": False, "logging_enabled": True,
           "encryption_in_transit": True},
          "Receives mobile-money payment callbacks via a function URL.", "payments", discovered_days=240,
          tags=["payments", "webhook"]),
    asset("a-lambda-002", "nightly-report-generator", "lambda_function", "Lambda", "internal", "financial",
          "medium",
          {"least_privilege": False, "logging_enabled": True},
          "Builds nightly finance reports into the finance archive bucket.", "finance",
          discovered_days=230, tags=["reporting"]),
    # --- CloudTrail ---
    asset("a-ct-001", "srf-org-trail", "cloudtrail_trail", "CloudTrail", "internal", "internal", "high",
          {"logging_enabled": True, "encryption_at_rest": True},
          "Organization-wide multi-region trail.", "security", region="global", discovered_days=400,
          tags=["audit"]),
    asset("a-ct-002", "srf-eu-west-1-trail", "cloudtrail_trail", "CloudTrail", "internal", "internal",
          "high",
          {"logging_enabled": False, "encryption_at_rest": True},
          "Regional trail for eu-west-1 where the payments integration runs.", "security",
          region="eu-west-1", discovered_days=380, tags=["audit"]),
    # --- org-002 (small organization with few risks) ---
    asset("b-s3-001", "kilima-member-records", "s3_bucket", "S3", "internal", "pii", "high",
          {"encryption_at_rest": False, "logging_enabled": False},
          "Member farmer registration forms and payout details.", "office", org=ORG2,
          discovered_days=200, tags=["members"]),
    asset("b-iam-001", "kilima-admin", "iam_user", "IAM", "public", "internal", "high",
          {"mfa_enforced": False, "logging_enabled": True},
          "Single administrator IAM user.", "office", region="global", org=ORG2, discovered_days=200),
    asset("b-ec2-001", "kilima-website", "ec2_instance", "EC2", "public", "public", "low",
          {"network_restricted": True, "logging_enabled": True},
          "WordPress website for the cooperative.", "office", org=ORG2, discovered_days=200),
]

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

_finding_counter = {"n": 0}


def finding(asset_id, title, description, category, severity, exposure, exploitability, source, days, status="open",
            exploitation_confirmed=False, org=ORG):
    _finding_counter["n"] += 1
    service = next(a["service"] for a in ASSETS if a["asset_id"] == asset_id)
    return {
        "finding_id": f"FND-{_finding_counter['n']:04d}",
        "organization_id": org,
        "asset_id": asset_id,
        "service": service,
        "title": title,
        "description": description,
        "category": category,
        "severity": severity,
        "exposure": exposure,
        "exploitability": exploitability,
        "exploitation_confirmed": exploitation_confirmed,
        "detection_source": source,
        "detected_at": days_ago(days, 6, 15),
        "status": status,
    }


FINDINGS = [
    # a-s3-001 customer KYC bucket
    finding("a-s3-001", "S3 bucket allows public read access",
            "Bucket policy grants s3:GetObject to Principal '*'; Block Public Access is disabled.",
            "network_exposure", "critical", "public", "trivial", "AWS Security Hub", 21),
    finding("a-s3-001", "S3 bucket default encryption disabled",
            "Objects are stored without SSE-S3 or SSE-KMS default encryption.",
            "unencrypted_storage", "high", "public", "conditional", "AWS Config", 21),
    finding("a-s3-001", "S3 server access logging disabled",
            "No server access logs are written, limiting investigation of object downloads.",
            "logging_disabled", "medium", "public", "difficult", "AWS Config", 21),
    finding("a-s3-001", "Anomalous anonymous S3 object listing",
            "GuardDuty observed ListObjects and bulk GetObject calls from an anonymous principal "
            "at 203.0.113.61 (Netherlands).",
            "threat_detection", "high", "public", "easy", "Amazon GuardDuty", 6),
    # a-s3-002 marketing website
    finding("a-s3-002", "Public S3 bucket (static website hosting)",
            "Bucket is public by design to serve website assets; reviewed and accepted.",
            "network_exposure", "low", "public", "trivial", "AWS Security Hub", 120, status="accepted_risk"),
    finding("a-s3-002", "S3 bucket versioning disabled",
            "Overwritten or deleted website assets cannot be recovered.",
            "backup_disabled", "low", "public", "difficult", "AWS Config", 95),
    # a-s3-003 finance archive
    finding("a-s3-003", "S3 bucket default encryption disabled",
            "Finance archive objects are stored unencrypted at rest.",
            "unencrypted_storage", "high", "internal", "conditional", "AWS Config", 40),
    finding("a-s3-003", "Bucket policy grants read to all IAM principals in the account",
            "Policy allows s3:GetObject for arn:aws:iam::111122223333:root, granting every role access.",
            "excessive_permissions", "medium", "internal", "conditional", "Prowler", 40, status="in_progress"),
    # a-s3-004 application logs
    finding("a-s3-004", "No lifecycle policy on log bucket",
            "Logs are retained indefinitely, increasing storage cost and data retention exposure.",
            "data_retention", "low", "internal", "none", "Prowler", 70),
    # a-s3-005 cloudtrail logs
    finding("a-s3-005", "MFA delete not enabled on CloudTrail bucket",
            "Versioned objects could be deleted without MFA.", "backup_disabled", "low", "internal",
            "difficult", "Prowler", 110, status="resolved"),
    # a-iam-001 ops-admin
    finding("a-iam-001", "Administrator IAM user without MFA",
            "IAM user ops-admin has console access and AdministratorAccess but no MFA device.",
            "missing_mfa", "critical", "public", "easy", "AWS Security Hub", 30),
    finding("a-iam-001", "Access key older than 365 days",
            "Active access key AKIA****EXAMPLE1 was created 455 days ago and never rotated.",
            "stale_credentials", "high", "public", "conditional", "AWS Security Hub", 30),
    finding("a-iam-001", "Shared administrator account",
            "ops-admin is used by several engineers, preventing individual accountability.",
            "excessive_permissions", "medium", "internal", "conditional", "Manual review", 25),
    # a-iam-002 ci-deploy-role
    finding("a-iam-002", "CI role has AdministratorAccess",
            "ci-deploy-role is attached to AdministratorAccess instead of a scoped deployment policy.",
            "excessive_permissions", "high", "internal", "conditional", "IAM Access Analyzer", 50),
    finding("a-iam-002", "CI role trust policy not restricted to main branch",
            "OIDC trust policy accepts tokens from any branch of the deployment repository.",
            "excessive_permissions", "medium", "internal", "conditional", "Manual review", 50),
    # a-iam-003 svc-payments
    finding("a-iam-003", "Service account access key older than 365 days",
            "svc-payments access key is 412 days old with no rotation process.",
            "stale_credentials", "high", "internal", "conditional", "AWS Security Hub", 35),
    # a-iam-005 platform-admin-sso
    finding("a-iam-005", "Permission set session duration exceeds policy",
            "Session duration is 12 hours; policy maximum is 4 hours for administrator access.",
            "session_management", "low", "internal", "difficult", "Manual review", 15),
    # a-ec2-001 bastion
    finding("a-ec2-001", "Security group allows SSH from 0.0.0.0/0",
            "sg-0bastion0001 permits TCP/22 from any IPv4 address.",
            "network_exposure", "high", "public", "easy", "AWS Security Hub", 60),
    finding("a-ec2-001", "SSH password authentication enabled",
            "sshd_config has PasswordAuthentication yes; keys are not enforced.",
            "weak_authentication", "high", "public", "easy", "Amazon Inspector", 60),
    finding("a-ec2-001", "Instance metadata service v1 enabled",
            "IMDSv1 is enabled, allowing SSRF-style credential theft.",
            "insecure_configuration", "medium", "internal", "conditional", "AWS Security Hub", 60),
    # a-ec2-002 web frontend
    finding("a-ec2-002", "TLS 1.0 enabled on HTTPS listener",
            "The web server still negotiates TLS 1.0.", "weak_encryption_in_transit", "medium", "public",
            "difficult", "Prowler", 45),
    finding("a-ec2-002", "nginx version with known CVE",
            "Inspector reports nginx 1.18 affected by a known HTTP/2 denial-of-service vulnerability.",
            "vulnerable_software", "medium", "public", "conditional", "Amazon Inspector", 20),
    # a-ec2-003 batch worker
    finding("a-ec2-003", "Kernel missing security updates",
            "Instance kernel is two minor versions behind with local privilege escalation fixes pending.",
            "vulnerable_software", "medium", "internal", "difficult", "Amazon Inspector", 18),
    # a-ec2-004 legacy reporting
    finding("a-ec2-004", "RDP open to the internet",
            "Security group permits TCP/3389 from 0.0.0.0/0.", "network_exposure", "critical", "public",
            "easy", "AWS Security Hub", 12),
    finding("a-ec2-004", "Unsupported operating system",
            "Windows Server 2012 R2 is past end of extended support and no longer receives patches.",
            "vulnerable_software", "high", "public", "easy", "Amazon Inspector", 12),
    finding("a-ec2-004", "EBS volume not encrypted",
            "Root and data volumes holding ledger extracts are unencrypted.",
            "unencrypted_storage", "medium", "internal", "conditional", "AWS Config", 12),
    # a-rds-001 customer db
    finding("a-rds-001", "RDS instance publicly accessible",
            "PubliclyAccessible=true with a public endpoint.", "network_exposure", "critical", "public", "easy",
            "AWS Security Hub", 16),
    finding("a-rds-001", "Database security group allows 5432 from 0.0.0.0/0",
            "sg-0custdb00001 permits PostgreSQL connections from any address.",
            "network_exposure", "high", "public", "easy", "AWS Security Hub", 16),
    finding("a-rds-001", "IAM database authentication disabled",
            "Database relies solely on static passwords.", "weak_authentication", "low", "internal",
            "difficult", "Prowler", 16),
    # a-rds-002 payments ledger
    finding("a-rds-002", "Minor engine version behind",
            "PostgreSQL 15.4; 15.7 contains security fixes.", "vulnerable_software", "low", "internal",
            "difficult", "AWS Trusted Advisor", 28),
    # a-rds-003 analytics replica
    finding("a-rds-003", "RDS storage not encrypted",
            "Analytics replica storage encryption is disabled.", "unencrypted_storage", "high", "internal",
            "conditional", "AWS Config", 55),
    finding("a-rds-003", "Automated backups disabled",
            "BackupRetentionPeriod is 0.", "backup_disabled", "medium", "internal", "none", "AWS Config", 55),
    finding("a-rds-003", "Production PII copied to staging",
            "Customer PII is replicated into a staging environment without masking.",
            "data_handling", "high", "internal", None, "Manual review", 55),
    # a-kms-001 customer data key
    finding("a-kms-001", "KMS key rotation disabled",
            "Automatic annual rotation is disabled for customer-data-key.",
            "key_rotation_disabled", "medium", "internal", "difficult", "AWS Security Hub", 80),
    finding("a-kms-001", "Key policy grants kms:* to CI role",
            "ci-deploy-role can administer and use the customer data key.",
            "excessive_permissions", "medium", "internal", "conditional", "IAM Access Analyzer", 50),
    # a-lambda-001 webhook
    finding("a-lambda-001", "Lambda function URL with AuthType NONE",
            "The payment webhook URL accepts unauthenticated requests without signature validation.",
            "network_exposure", "high", "public", "easy", "AWS Security Hub", 26),
    finding("a-lambda-001", "Secrets stored in plaintext environment variables",
            "MOBILE_MONEY_API_SECRET is stored as a plaintext environment variable.",
            "secrets_exposure", "high", "internal", "conditional", "Prowler", 26),
    finding("a-lambda-001", "Deprecated Lambda runtime",
            "Function runs on python3.8, which no longer receives security updates.",
            "vulnerable_software", "medium", "internal", "difficult", "AWS Trusted Advisor", 26),
    # a-lambda-002 nightly reports
    finding("a-lambda-002", "Execution role can read all S3 buckets",
            "Role uses s3:* on *, including the KYC and CloudTrail buckets.",
            "excessive_permissions", "medium", "internal", "conditional", "IAM Access Analyzer", 44),
    # a-ct-002 eu-west-1 trail
    finding("a-ct-002", "CloudTrail logging stopped in eu-west-1",
            "The regional trail has been stopped for 19 days; API activity there is not recorded.",
            "logging_disabled", "high", "internal", "difficult", "AWS Security Hub", 19),
    finding("a-ct-002", "CloudTrail not integrated with CloudWatch Logs",
            "No metric filters or alarms exist for this trail.", "logging_disabled", "low", "internal",
            "difficult", "Prowler", 90, status="resolved"),
    # org-002
    finding("b-s3-001", "Member records bucket not encrypted",
            "Bucket holding member ID numbers and M-Pesa payout numbers has no default encryption.",
            "unencrypted_storage", "high", "internal", "conditional", "AWS Config", 30, org=ORG2),
    finding("b-iam-001", "Administrator IAM user without MFA",
            "kilima-admin has console access and AdministratorAccess but no MFA device.",
            "missing_mfa", "high", "public", "easy", "AWS Security Hub", 30, org=ORG2),
    finding("b-ec2-001", "Outdated WordPress plugins",
            "Three WordPress plugins have published security updates.", "vulnerable_software", "medium",
            "public", "conditional", "Manual review", 30, org=ORG2),
]

# ---------------------------------------------------------------------------
# Data inventory
# ---------------------------------------------------------------------------


def inv(asset_id, classification, categories, pii, financial, count, location, note=None, org=ORG):
    return {
        "asset_id": asset_id,
        "organization_id": org,
        "data_classification": classification,
        "data_categories": categories,
        "contains_pii": pii,
        "contains_financial_data": financial,
        "record_count": count,
        "record_count_note": note,
        "storage_location": location,
    }


DATA_INVENTORY = [
    inv("a-s3-001", "Restricted - regulated", ["national_id_scans", "payslips", "selfies"], True, True, 412_000,
        "s3://srf-customer-kyc-documents (af-south-1)"),
    inv("a-s3-002", "Public", ["website_images", "brochures"], False, False, 1_850,
        "s3://srf-marketing-website (af-south-1)"),
    inv("a-s3-003", "Confidential", ["management_accounts", "loan_book_exports"], False, True, None,
        "s3://srf-finance-reports-archive (af-south-1)", note="Archive has never been inventoried"),
    inv("a-s3-004", "Internal", ["application_logs"], False, False, 2_400_000,
        "s3://srf-application-logs (af-south-1)"),
    inv("a-s3-005", "Confidential", ["audit_logs"], False, False, 1_100_000,
        "s3://srf-cloudtrail-logs (af-south-1)"),
    inv("a-ec2-003", "Confidential", ["credit_scores_temp"], True, False, 15_000,
        "EBS vol-0batch0001 (af-south-1)"),
    inv("a-ec2-004", "Confidential", ["ledger_extracts"], True, True, None,
        "EBS vol-0legacy001 (af-south-1)", note="Unknown: server was not in the asset register"),
    inv("a-rds-001", "Restricted - regulated", ["customer_profiles", "contact_details", "loan_balances"], True, True,
        1_284_000, "RDS srf-customer-db (af-south-1)"),
    inv("a-rds-002", "Restricted - regulated", ["disbursements", "repayments"], True, True, 3_412_000,
        "RDS srf-payments-ledger (af-south-1)"),
    inv("a-rds-003", "Restricted - regulated", ["customer_profiles"], True, False, None,
        "RDS srf-analytics-replica (af-south-1)", note="Replica refreshed ad hoc; row count not tracked"),
    inv("b-s3-001", "Restricted - regulated", ["member_ids", "payout_numbers"], True, True, 8_400,
        "s3://kilima-member-records (af-south-1)", org=ORG2),
]

# ---------------------------------------------------------------------------
# Authentication / access logs
# ---------------------------------------------------------------------------

LOCATIONS = {
    "nairobi_office": ("Kenya", "KE", "Nairobi", -1.2921, 36.8219, ["192.0.2.10", "192.0.2.11", "192.0.2.12"]),
    "nairobi_home": ("Kenya", "KE", "Nairobi", -1.2864, 36.8172, ["192.0.2.21", "192.0.2.22", "192.0.2.23"]),
    "mombasa": ("Kenya", "KE", "Mombasa", -4.0435, 39.6682, ["192.0.2.41"]),
    "nyeri": ("Kenya", "KE", "Nyeri", -0.4201, 36.9476, ["192.0.2.80", "192.0.2.81"]),
    "london": ("United Kingdom", "GB", "London", 51.5074, -0.1278, ["192.0.2.60", "192.0.2.61"]),
    "berlin": ("Germany", "DE", "Berlin", 52.5200, 13.4050, ["198.51.100.10", "198.51.100.11"]),
    "dublin_aws": ("Ireland", "IE", "Dublin", 53.3498, -6.2603, ["198.51.100.50", "198.51.100.51"]),
    "sao_paulo": ("Brazil", "BR", "Sao Paulo", -23.5505, -46.6333, ["203.0.113.77"]),
    "amsterdam": ("Netherlands", "NL", "Amsterdam", 52.3676, 4.9041, ["203.0.113.45", "203.0.113.61", "203.0.113.150"]),
    "singapore": ("Singapore", "SG", "Singapore", 1.3521, 103.8198, ["203.0.113.88"]),
}

UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
UA_SSH = "OpenSSH_9.6"
UA_SDK = "aws-sdk-python/1.34 Python/3.12 Linux"
UA_PSQL = "psql/15.6"


class EventBuilder:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events: List[Dict] = []

    def add(self, ts: datetime, username: str, user_type: str, location: str, outcome: str, method: str,
            action: str, asset_id: str, privileged: bool = False, user_agent: Optional[str] = UA_BROWSER,
            records: Optional[int] = None, failure_reason: Optional[str] = None, ip: Optional[str] = None,
            org: str = ORG) -> None:
        country, code, city, lat, lon, ips = LOCATIONS[location]
        self.events.append({
            "organization_id": org,
            "timestamp": iso(ts),
            "username": username,
            "user_type": user_type,
            "privileged": privileged,
            "source_ip": ip or self.rng.choice(ips),
            "country": country,
            "country_code": code,
            "city": city,
            "latitude": lat,
            "longitude": lon,
            "outcome": outcome,
            "auth_method": method,
            "action": action,
            "asset_id": asset_id,
            "user_agent": user_agent,
            "records_accessed": records,
            "failure_reason": failure_reason,
        })


def workday_times(rng, tz, start_day, end_day, probability, hour_range=(9, 17), skip=()):
    """Yield local working-hour timestamps on weekdays with the given probability per day."""
    day = start_day
    while day < end_day:
        local_date = day.astimezone(tz).date()
        if local_date.weekday() < 5 and local_date not in skip and rng.random() < probability:
            hour = rng.randint(hour_range[0], hour_range[1] - 1)
            minute = rng.randint(0, 59)
            local = datetime(local_date.year, local_date.month, local_date.day, hour, minute, tzinfo=tz)
            yield local.astimezone(timezone.utc)
        day += timedelta(days=1)


def generate_auth_logs(rng: random.Random) -> List[Dict]:
    b = EventBuilder(rng)
    start = REF - timedelta(days=config.HISTORICAL_WINDOW_DAYS + config.DATASET_LEAD_IN_DAYS)
    end = REF

    # Scenario days excluded from baselines so the planted events stay clean.
    alice_cutoff = REF - timedelta(days=3)
    carol_skip = {datetime(2026, 10, 28).date(), datetime(2026, 10, 29).date(), datetime(2026, 10, 30).date()}

    # --- alice.wanjiru: analyst, Nairobi, reads the customer database -------------
    for ts in workday_times(rng, NAIROBI, start, alice_cutoff, 0.45):
        b.add(ts, "alice.wanjiru", "human", "nairobi_office", "success", "password", "data_read", "a-rds-001",
              user_agent=UA_PSQL, records=rng.randint(80, 400))

    # --- brian.otieno: engineer, Nairobi / Mombasa, SSH via bastion ---------------
    for ts in workday_times(rng, NAIROBI, start, end, 0.30):
        location = "mombasa" if rng.random() < 0.2 else "nairobi_office"
        target = rng.choice(["a-ec2-001", "a-ec2-003"])
        if rng.random() < 0.15:  # occasional typo, well below the brute-force threshold
            b.add(ts - timedelta(minutes=1), "brian.otieno", "human", location, "failure", "ssh_key", "ssh_login",
                  target, user_agent=UA_SSH, failure_reason="invalid_key_passphrase")
        b.add(ts, "brian.otieno", "human", location, "success", "ssh_key", "ssh_login", target, user_agent=UA_SSH)

    # --- carol.mendes: finance, alternates Nairobi and London by ISO week ---------
    for ts in workday_times(rng, NAIROBI, start, end, 0.40, skip=carol_skip):
        in_london = ts.isocalendar()[1] % 2 == 0
        tz = LONDON if in_london else NAIROBI
        local = ts.astimezone(NAIROBI)
        ts = datetime(local.year, local.month, local.day, local.hour, local.minute, tzinfo=tz).astimezone(timezone.utc)
        b.add(ts, "carol.mendes", "human", "london" if in_london else "nairobi_office", "success", "password_mfa",
              "data_read", "a-s3-003", user_agent=UA_MAC, records=rng.randint(15, 120))

    # --- emma.schultz: remote engineer, Berlin -----------------------------------
    for ts in workday_times(rng, BERLIN, start, end, 0.30):
        target = rng.choice(["a-ec2-002", "a-lambda-001"])
        b.add(ts, "emma.schultz", "human", "berlin", "success", "sso_mfa", "console_login", target)

    # --- grace.njeri: security analyst using the audit role ----------------------
    for ts in workday_times(rng, NAIROBI, start, end, 0.20):
        b.add(ts, "grace.njeri", "human", "nairobi_office", "success", "sso_mfa", "assume_role", "a-iam-004")

    # --- ops-admin: shared admin IAM user, working hours only --------------------
    for ts in workday_times(rng, NAIROBI, start, end, 0.35, hour_range=(9, 17)):
        b.add(ts, "ops-admin", "admin", "nairobi_office", "success", "password", "console_login", "a-iam-001",
              privileged=True)

    # --- david.kim: platform admin via SSO, working hours only -------------------
    for ts in workday_times(rng, NAIROBI, start, end, 0.30, hour_range=(9, 17)):
        b.add(ts, "david.kim", "admin", "nairobi_office", "success", "sso_mfa", "console_login", "a-iam-005",
              privileged=True)

    # --- service accounts (Dublin / eu-west-1 workloads) ------------------------
    day = start
    while day < end:
        if (day - start).days % 3 == 0:
            ts = day.replace(hour=rng.randint(6, 16), minute=rng.randint(0, 59))
            b.add(ts, "svc-payments", "service", "dublin_aws", "success", "access_key", "api_call", "a-rds-002",
                  user_agent=UA_SDK, records=rng.randint(50, 500))
        if (day - start).days % 4 == 0:
            ts = day.replace(hour=22, minute=rng.randint(0, 30))  # 01:00 Nairobi: expected batch window
            b.add(ts, "svc-reporting", "service", "dublin_aws", "success", "assume_role", "data_read", "a-s3-003",
                  user_agent=UA_SDK, records=rng.randint(2_000, 3_000))
        if (day - start).days % 5 == 2:
            ts = day.replace(hour=rng.randint(7, 15), minute=rng.randint(0, 59))
            b.add(ts, "svc-ci", "service", "dublin_aws", "success", "web_identity", "assume_role", "a-iam-002",
                  user_agent=UA_SDK)
        day += timedelta(days=1)

    # =====================================================================
    # Planted scenarios (fixed times relative to the 2026-11-06 reference)
    # =====================================================================

    # 1. Credential stuffing against ops-admin: 8 failures in 8 minutes from Amsterdam.
    for i in range(8):
        b.add(at("2026-11-03T02:10:00Z") + timedelta(minutes=i, seconds=7 * i), "ops-admin", "admin", "amsterdam",
              "failure", "password", "console_login", "a-iam-001", privileged=True,
              user_agent="python-requests/2.31", failure_reason="invalid_password", ip="203.0.113.45")

    # 2. SSH brute force against the bastion: 14 failures in ~10 minutes from Singapore.
    for i, user in enumerate(["root", "admin", "ubuntu", "ec2-user", "test", "root", "oracle", "admin",
                              "postgres", "root", "deploy", "ubuntu", "git", "root"]):
        b.add(at("2026-10-25T23:02:00Z") + timedelta(seconds=43 * i), user, "human", "singapore", "failure",
              "ssh_password", "ssh_login", "a-ec2-001", privileged=user == "root", user_agent="libssh_0.9.6",
              failure_reason="invalid_credentials", ip="203.0.113.88")

    # 3. Historical SSH brute force against the bastion (47 days ago).
    for i, user in enumerate(["root", "admin", "ubuntu", "root", "pi", "admin", "root", "user", "root"]):
        b.add(at("2026-09-20T03:15:00Z") + timedelta(seconds=75 * i), user, "human", "amsterdam", "failure",
              "ssh_password", "ssh_login", "a-ec2-001", privileged=user == "root", user_agent="libssh_0.9.6",
              failure_reason="invalid_credentials", ip="203.0.113.150")

    # 4. Below-threshold failures (emma mistypes her password 4 times) - must NOT be flagged.
    for i in range(4):
        b.add(at("2026-10-20T07:30:00Z") + timedelta(minutes=i), "emma.schultz", "human", "berlin", "failure",
              "sso_mfa", "console_login", "a-ec2-002", failure_reason="invalid_password", ip="198.51.100.10")

    # 5. New country + unusual data access: alice from Sao Paulo, then a bulk read.
    b.add(at("2026-11-04T23:40:00Z"), "alice.wanjiru", "human", "sao_paulo", "success", "password",
          "console_login", "a-rds-001", user_agent=UA_BROWSER, ip="203.0.113.77")
    b.add(at("2026-11-04T23:52:00Z"), "alice.wanjiru", "human", "sao_paulo", "success", "password",
          "data_read", "a-rds-001", user_agent=UA_PSQL, records=48_500, ip="203.0.113.77")

    # 6. Impossible travel: carol in Nairobi, then London under two hours later.
    b.add(at("2026-10-29T06:10:00Z"), "carol.mendes", "human", "nairobi_office", "success", "password_mfa",
          "data_read", "a-s3-003", user_agent=UA_MAC, records=64, ip="192.0.2.10")
    b.add(at("2026-10-29T08:05:00Z"), "carol.mendes", "human", "london", "success", "password_mfa",
          "data_read", "a-s3-003", user_agent=UA_MAC, records=71, ip="192.0.2.60")

    # 7. Off-hours admin activity: ops-admin at 01:40 Sunday Nairobi time creates an access key.
    b.add(at("2026-10-31T22:40:00Z"), "ops-admin", "admin", "nairobi_home", "success", "password", "console_login",
          "a-iam-001", privileged=True, ip="192.0.2.22")
    b.add(at("2026-10-31T22:47:00Z"), "ops-admin", "admin", "nairobi_home", "success", "password",
          "create_access_key", "a-iam-001", privileged=True, ip="192.0.2.22")

    # 8. Historical off-hours ops-admin activity (Sunday 00:15 local, 48 days ago).
    b.add(at("2026-09-19T21:15:00Z"), "ops-admin", "admin", "nairobi_home", "success", "password", "attach_policy",
          "a-iam-001", privileged=True, ip="192.0.2.21")

    # 9. Off-hours activity on a well-controlled asset (david.kim, Sunday 22:30 local, MFA).
    b.add(at("2026-10-25T19:30:00Z"), "david.kim", "admin", "nairobi_home", "success", "sso_mfa", "console_login",
          "a-iam-005", privileged=True, ip="192.0.2.23")

    # 10. Anonymous public-bucket access seen in S3 data events (no baseline -> not scored as unusual).
    b.add(at("2026-10-31T11:05:00Z"), "anonymous", "human", "amsterdam", "success", "none", "data_read",
          "a-s3-001", user_agent="aws-cli/2.15", records=1_240, ip="203.0.113.61")

    # --- org-002: small cooperative --------------------------------------------
    for ts in workday_times(rng, NAIROBI, REF - timedelta(days=60), end, 0.15):
        b.add(ts, "kilima-admin", "admin", "nyeri", "success", "password", "console_login", "b-iam-001",
              privileged=True, org=ORG2)

    events = sorted(b.events, key=lambda e: (e["timestamp"], e["username"], e["action"], e["source_ip"]))
    for index, event in enumerate(events, start=1):
        event["event_id"] = f"EVT-{index:05d}"
    key_order = ["event_id", "organization_id", "timestamp", "username", "user_type", "privileged", "source_ip",
                 "country", "country_code", "city", "latitude", "longitude", "outcome", "auth_method", "action", "asset_id",
                 "user_agent", "records_accessed", "failure_reason"]
    return [{k: e[k] for k in key_order} for e in events]


# ---------------------------------------------------------------------------
# Anomaly snapshot (detection history)
# ---------------------------------------------------------------------------


def generate_anomaly_snapshot(auth_logs: List[Dict]) -> Dict:
    from analysis.detectors import run_detectors
    from api.schemas.auth_logs import AuthEvent

    events = [AuthEvent.model_validate(e) for e in auth_logs]
    runs, anomalies = [], []
    for org in ORGANIZATIONS:
        org_events = [e for e in events if e.organization_id == org["organization_id"]]
        found = run_detectors(org_events, config.DEFAULT_ASSESSMENT_START, config.DEFAULT_ASSESSMENT_END)
        runs.append({
            "organization_id": org["organization_id"],
            "run_at": iso(REF),
            "analysis_start": iso(config.DEFAULT_ASSESSMENT_START),
            "analysis_end": iso(config.DEFAULT_ASSESSMENT_END),
            "anomaly_count": len(found),
        })
        anomalies.extend(a.model_dump(mode="json") for a in found)
    return {
        "description": "Snapshot of anomaly detection runs at the reference time. The API re-runs detection "
                       "live from auth_logs.json; this file records detection history.",
        "detection_runs": runs,
        "anomalies": anomalies,
    }


def write_json(path: Path, data) -> None:
    # Always LF line endings so the files are byte-identical on every OS.
    path.write_bytes((json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def main(output_dir: Path = config.DATA_DIR) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(config.DEMO_DATA_SEED)
    auth_logs = generate_auth_logs(rng)
    files = {
        "organizations": ORGANIZATIONS,
        "assets": ASSETS,
        "findings": FINDINGS,
        "auth_logs": auth_logs,
        "data_inventory": DATA_INVENTORY,
        "anomalies": generate_anomaly_snapshot(auth_logs),
    }
    for key, data in files.items():
        write_json(output_dir / config.DATA_FILES[key], data)
    print(f"Wrote demo data to {output_dir}: {len(ASSETS)} assets, {len(FINDINGS)} findings, "
          f"{len(auth_logs)} auth events, {len(files['anomalies']['anomalies'])} anomalies")


if __name__ == "__main__":
    main()
