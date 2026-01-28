import boto3
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

try:
    ec2 = boto3.client("ec2")

except NoCredentialsError:
    logger.error("AWS credentials not found. Please configure your AWS credentials.")
    exit(1)


def check_ami_age(instance: dict, ec2_client, max_age_days: int = 180) -> list[dict]:
    """
    Check whether the AMI used by an EC2 instance is older than the allowed threshold.

    Frameworks:
        - CIS 4.5: Ensure the use of up-to-date and secure AMIs
        - NIST SI-2: Flaw Remediation (keeping systems updated)

    Args:
        instance (dict): EC2 instance dictionary from describe_instances()
        ec2_client: Boto3 EC2 client
        max_age_days (int): Maximum allowed AMI age in days

    Returns:
        list[dict]: Audit results for AMI age check
    """
    ami_id = instance.get("ImageId")

    if not ami_id:
        return [{
            "check": "AMI Age",
            "status": "FAIL",
            "severity": "Medium",
            "details": "Instance does not have an ImageId"
        }]

    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])
        images = response.get("Images", [])

        if not images:
            return [{
                "check": "AMI Age",
                "status": "FAIL",
                "severity": "Medium",
                "details": f"AMI {ami_id} not found or may be deregistered"
            }]

        image = images[0]
        creation_str = image.get("CreationDate")

        if not creation_str:
            return [{
                "check": "AMI Age",
                "status": "FAIL",
                "severity": "Medium",
                "details": f"AMI {ami_id} missing CreationDate metadata"
            }]

        # Parse AWS timestamp: "YYYY-MM-DDTHH:MM:SS.sssZ"
        creation_dt = datetime.strptime(creation_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )

        now = datetime.now(timezone.utc)
        age_days = (now - creation_dt).days

        if age_days > max_age_days:
            return [{
                "check": "AMI Age",
                "status": "FAIL",
                "severity": "Medium",
                "details": (
                    f"AMI {ami_id} is {age_days} days old "
                    f"(exceeds threshold of {max_age_days} days)"
                ),
            }]

        return [{
            "check": "AMI Age",
            "status": "PASS",
            "details": f"AMI {ami_id} is {age_days} days old",
        }]

    except ClientError as e:
        logger.error(f"Error checking AMI {ami_id} for instance {instance.get('InstanceId')}: {e}")
        return [{
            "check": "AMI Age",
            "status": "FAIL",
            "severity": "Medium",
            "details": f"ClientError while checking AMI {ami_id}: {str(e)}",
        }]
    except Exception as e:
        logger.error(f"Unexpected error checking AMI {ami_id}: {e}")
        return [{
            "check": "AMI Age",
            "status": "FAIL",
            "severity": "Medium",
            "details": f"Unexpected error: {str(e)}",
        }]