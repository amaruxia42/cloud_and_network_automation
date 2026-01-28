AWS S3 Security Audit

## Overview

This module performs an automated security audit of Amazon S3 buckets to identify common misconfigurations that may lead to data exposure, compliance gaps, or weakened security posture.

The audit focuses on **preventative and detective controls** across access management, encryption, logging, and data protection, aligned with AWS best practices and industry security frameworks.

---

## What This Audit Checks

The S3 audit evaluates the following security controls:

### Public Access Exposure
- Bucket ACLs allowing public access
- Bucket policies with wildcard principals
- Public Access Block configuration enforcement

### Encryption
- Server-side encryption using AES256 or AWS KMS
- Detection of unencrypted buckets

### Logging & Monitoring
- S3 access logging configuration
- Bucket event notifications (SNS, SQS, Lambda, EventBridge)

### Data Protection
- Object versioning status
- MFA Delete configuration

### CORS Configuration
- Detection of overly permissive CORS rules
- Identification of wildcard origins and unsafe HTTP methods

---

## Framework Alignment

This audit aligns findings to recognised security standards:

**CIS AWS Foundations Benchmark**
- 2.1 – S3 public access
- 2.2 – Encryption at rest
- 2.6 – S3 logging

**NIST 800-53**
- AC-3 – Access Enforcement
- SC-13 – Cryptographic Protection
- AU-2 – Audit Events
- SC-7 – Boundary Protection

---

## Output

The audit produces a structured report containing:

- **Executive summary**
  - Total buckets audited
  - Buckets with findings
  - Issues by severity
- **Detailed findings**
  - Per-bucket results
  - Control-level failures with context and severity

Example finding:

{
  "check": "Public Access (Policy)",
  "status": "FAIL",
  "severity": "High",
  "details": "Bucket policy allows public access"
}

---

## Required IAM Permissions

This audit is **read-only** and requires limited IAM permissions to assess S3 security controls.

The following permissions are required to execute the audit:

### Permissions Used
- List S3 buckets in the account
- Inspect bucket access controls (ACLs and policies)
- Validate encryption, logging, and versioning configuration
- Review CORS rules, MFA Delete status, and event notifications
- Check Public Access Block enforcement

### Minimum IAM Policy

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketVersioning",
        "s3:GetBucketCors",
        "s3:GetBucketNotification",
        "s3:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}

## 🧪 Example Command

```bash
python audit_s3.py --buckets my-bucket-1 my-bucket-2 --format json


