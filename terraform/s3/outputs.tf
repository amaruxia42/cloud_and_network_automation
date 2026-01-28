output "test_buckets" {
  value = {
    for k, v in aws_s3_bucket.test_buckets : k => v.bucket
  }
}

output "logging_buckets" {
  value = {
    for k, v in aws_s3_bucket.test_buckets : k => v.id
  }
}