import boto3
from botocore.config import Config
from botocore.exceptions import NoCredentialsError
from datetime import datetime, timezone
from shared.frameworks import get_framework
from shared.report import AUDIT_RUN_ID


retry_config = Config(
    retries={
        "max_attempts": 5,
        "mode": "standard"
    }
)


def get_cloudtrail():
    try:
        return boto3.client("cloudtrail", config=retry_config)
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not found.")


def get_ec2():
    try:
        return boto3.client("ec2", config=retry_config)
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not found.")


def get_dynamodb():
    try:
        return boto3.client("dynamodb", config=retry_config)
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not found.")


def get_app_autoscaling():
    try:
        return boto3.client("application-autoscaling", config=retry_config)
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not found.")


def get_iam():
    try:
        return boto3.client("iam", config=retry_config)
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not found.")


def get_s3():
    try:
        return boto3.client("s3", config=retry_config)
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not found.")



# ---- This function will be phased out in the V2 auditors -----
def audit_metadata(results, *, service: str):
    """
    Execute a check safely and return standardised findings.
    """
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%d-%m-%Y %H:%M:%S.%f") + f"{now.microsecond // 1000:03d}"

    def _augment(item: dict) -> dict:
        item = item.copy() # Make a copy of the dict to avoid mutation

        item["timestamp"] = timestamp
        item["audit_run_id"] = AUDIT_RUN_ID

        # ----- Framework lookup -----
        check_key = item.get("check_key")
        if check_key:
            framework = get_framework(service, check_key)
            if framework:
                item["framework"] = framework

        # ----- Remove internal-only fields -----
        item.pop("check_key", None)

        return item

    if isinstance(results, list):
        return [_augment(item) for item in results]
    elif isinstance(results, dict):
        return _augment(results)
    else:
        raise TypeError(f"Unsupported result type {type(results)}")





