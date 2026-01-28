import argparse
from datetime import datetime, timezone
from pathlib import Path
from shared.logger import get_logger
from shared.report import ServicesAuditReport
from aws_cloudtrail_audit.cloudtrail_audit import run_cloudtrail_audit
from aws_ec2_audit.ec2_audit import run_ec2_audit
from aws_dynamodb_audit.dynamodb_audit import run_dynamodb_audit
from aws_iam_audit.iam_audit import run_iam_audit
from aws_s3_audit.s3_audit import run_s3_audit
from aws_vpc_audit.vpc_audit import run_vpc_audit

logger = get_logger(__name__)

AWS_AUDITS = {
    "dynamodb": run_dynamodb_audit,
    "ec2": run_ec2_audit,
    "iam": run_iam_audit,
    "s3": run_s3_audit,
    "vpc": run_vpc_audit,
    "cloudtrail": run_cloudtrail_audit,
}


def determine__service_report_name(services: list[str]) -> str:
    if len(services) == 1:
        return f"{services[0].lower()}_results"
    return "aws_services_audit_results"


def main():
    parser = argparse.ArgumentParser(description="AWS Security Benchmark Audit Toolkit")

    parser.add_argument(
        "--services",
        nargs="+",
        choices=list(AWS_AUDITS.keys()) + ["all"],
        default=["all"],
        help="AWS services to audit"
    )

    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output file format"
    )

    args = parser.parse_args()

    selected_services = (
        AWS_AUDITS.keys()
        if "all" in args.services
        else args.services
    )

    logger.info("Selected services: %s", ", ".join(selected_services))

    all_findings = []

    for service_name in selected_services:
        logger.info("Running %s audit", service_name)
        audit_func = AWS_AUDITS[service_name]

        findings = audit_func()
        all_findings.extend(findings)

    if not all_findings:
        logger.warning("No audit findings generated - no report created")
        return

    report_basename = determine__service_report_name(selected_services)

    build_report(
        findings=all_findings,
        output=args.format,
        basename=report_basename
    )

    logger.info("AWS security audit completed")


def build_report(
    findings: list,
    output: str,
    basename: str
):
    report = ServicesAuditReport(findings=findings)
    timestamp = datetime.now(timezone.utc).strftime("%d-%m-%Y-%H:%M:%S")
    results_dir = Path("Results")
    results_dir.mkdir(exist_ok=True)

    filename = results_dir / f"{basename}_{timestamp}.{output}"

    if output == "json":
        return report.to_json(f"{filename}")
    elif output == "csv":
        return report.to_csv(f"{filename}")

    raise ValueError(f"Unknown format: {output}")


if __name__ == "__main__":
    main()