# AWS VPC Security Audit

## Overview

This module performs a security audit of AWS VPC configurations to identify common network security misconfigurations that may expose cloud workloads to unintended access.
It is designed to support security engineering, cloud governance, and continuous security posture improvement across AWS environments.

The audit focuses on defence-in-depth controls at the network layer, aligned to industry security frameworks such as CIS AWS Foundations Benchmark and NIST 800-53.

⸻

## What This Audit Checks

# The VPC audit evaluates the following security controls:

 Security Group Exposure
	•	Identifies ingress rules allowing unrestricted access (0.0.0.0/0 or ::/0)
	•	Highlights exposed ports that may increase attack surface

 VPC Flow Logs
	•	Verifies whether VPC Flow Logs are enabled for network traffic visibility and forensic analysis

 Network ACL Configuration
	•	Detects overly permissive allow rules that may bypass security group protections

 Route Table Exposure
	•	Identifies route tables with direct Internet Gateway routes that may unintentionally expose subnets

⸻

Framework Alignment

This audit maps findings to widely adopted security standards:

CIS AWS Foundations Benchmark
	•	3.9 – Ensure VPC flow logging is enabled
	•	4.1 / 4.2 – Network security and security group configuration
	•	4.4 – VPC route table configuration

NIST 800-53
	•	AC-3 – Access Enforcement
	•	AC-4 – Information Flow Enforcement
	•	AU-2 – Audit Events
	•	SC-7 – Boundary Protection

⸻

Output

The audit generates a structured JSON report containing:
	•	Executive summary
	•	Total VPCs audited
	•	Number of affected VPCs
	•	Findings by severity
	•	Detailed findings
	•	Per-VPC results
	•	Specific control failures with context

Usage

Ensure AWS credentials are configured with permissions to read EC2 and VPC metadata.

python vpc_audit.py

The report is saved locally as:

vpc_audit_results.json

Intended Use Cases
	•	Cloud security posture reviews
	•	Pre-production security validation
	•	Security engineering and remediation planning
	•	Evidence gathering for compliance and audit activities

⸻

Limitations & Future Enhancements

Current scope focuses on core VPC controls. Planned improvements include:
	•	Refactoring to shared logging, framework mapping, and AWS client modules
	•	Support for VPC endpoints and private service exposure checks
	•	Parallel execution for large multi-VPC environments
	•	Integration with CI/CD pipelines and scheduled security scans

⸻

Disclaimer

This tool provides security visibility, not enforcement.
Findings should be reviewed in context and remediated according to organisational risk tolerance and architectural requirements.