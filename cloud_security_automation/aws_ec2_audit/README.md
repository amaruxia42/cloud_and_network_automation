AWS EC2 Security Audit

Overview

This module performs an automated security audit of Amazon EC2 instances to identify common misconfigurations that may expose compute resources, increase attack surface, or violate security best practices.

The audit focuses on network exposure, identity configuration, metadata protection, and data-at-rest controls, aligned with AWS security best practices and recognised compliance frameworks.

⸻

What This Audit Checks

The EC2 audit evaluates the following security controls:

Network Exposure
	•	EC2 instances with public IP addresses
	•	Security groups allowing unrestricted ingress (0.0.0.0/0 or ::/0)
	•	Detection of unrestricted SSH (22) or RDP (3389) access

Instance Hardening
	•	Enforcement of IMDSv2 (Instance Metadata Service v2)
	•	Detection of instances allowing legacy IMDSv1 access

Identity & Access Management
	•	Presence of an IAM instance profile
	•	Identification of instances running without an attached IAM role

Data Protection
	•	EBS volume encryption status for all attached volumes
	•	Detection of unencrypted EBS volumes

Backup & Snapshot Exposure
	•	Identification of publicly accessible EBS snapshots
	•	Detection of snapshot permissions allowing public volume creation

⸻

Framework Alignment

Findings are mapped to recognised security standards:

CIS AWS Foundations Benchmark
	•	4.1 / 4.2 – Security Group Rules
	•	4.3 / 4.4 – Unrestricted SSH and RDP Access
	•	4.9 – Public IP exposure
	•	4.29 – IMDSv2 enforcement
	•	2.2.1 – EBS volume encryption
	•	2.2.2 – Public EBS snapshots

NIST 800-53
	•	AC-3 – Access Enforcement
	•	AC-6 – Least Privilege
	•	IA-3 – Device Identification & Authentication
	•	SC-7 – Boundary Protection
	•	SC-28 – Protection of Information at Rest

⸻

Output

The audit produces a structured JSON report containing:

Executive Summary
	•	Total EC2 instances audited
	•	Instances with security findings
	•	Total findings by severity (High / Medium)

Detailed Results
	•	Per-instance findings
	•	Control-level failures with context and severity
	•	Account-level snapshot exposure findings

Example Finding

{
  "check": "Unrestricted SSH/RDP",
  "resource": "i-0abc123def456",
  "status": "FAIL",
  "severity": "High",
  "details": "Port 22 open to 0.0.0.0/0 in SG sg-0123456789"
}

Required IAM Permissions

This audit is read-only and does not modify AWS resources.

Permissions Used
	•	List EC2 instances and attached resources
	•	Inspect security groups and ingress rules
	•	Check EBS volume encryption status
	•	Review EBS snapshot permissions
	•	Read instance metadata configuration

Minimum IAM Policy

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSnapshotAttribute"
      ],
      "Resource": "*"
    }
  ]
}

Design Notes
	•	Instance-level and account-level checks are intentionally separated
	•	All checks return structured findings only (no PASS noise)
	•	PASS results are generated centrally in the audit orchestration layer
	•	AWS clients are injectable to support unit testing and mocking
	•	Severity handling is centralized for future tuning and scaling

⸻

Status

Version: v1
Audit Coverage: Core EC2 security baseline
Intended Use:
	•	Security posture assessment
	•	Portfolio demonstration
	•	Foundation for multi-service AWS audit framework
