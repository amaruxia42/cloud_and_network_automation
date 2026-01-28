terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_s3_bucket" "test_buckets" {
  for_each = var.test_bucket_tags
  bucket   = each.value.bucket_name

  tags = merge({
    Name        = each.value.bucket_name
    Environment = title(each.key)
  })
}

resource "aws_s3_bucket_versioning" "test_versioning" {
  for_each = var.test_bucket_tags
  bucket   = each.value.bucket_name

  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket" "logging_bucket" {
  bucket = "test-buckets-prod-dev-stage-logging"

  tags = {
    Name    = "Access Logs Bucket"
    Purpose = "Store access logs for test buckets"
  }
}

resource "aws_s3_bucket_logging" "test_logging" {
  for_each = var.test_bucket_tags

  bucket        = aws_s3_bucket.test_buckets[each.key].id
  target_bucket = aws_s3_bucket.logging_bucket.id
  target_prefix = "logs/${each.key}/"
}