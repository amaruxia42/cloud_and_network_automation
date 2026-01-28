
variable "test_bucket_tags" {
  description = "Environment-specific tags for S3 buckets"
  type = map(object({
    bucket_name = string
    owner       = string
    backup      = bool
  }))

  default = {
    dev = {
      bucket_name = "devops-development-bucket-88"
      owner       = "Wolverine"
      backup      = false
    }

    staging = {
      bucket_name = "devops-staging-bucket-88"
      owner       = "Spiderman"
      backup      = false
    }

    prod = {
      bucket_name = "devops-production-bucket-88"
      owner       = "Batman"
      backup      = false
    }
  }
}