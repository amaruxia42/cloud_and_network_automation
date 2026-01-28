variable "dynamodb_name" {
  description = "Dynamodb table name"
  type        = string

  default = "nautilus-db"
}

variable "dynamodb_table_tags" {
  description = "Environment-specific tags for dynamodb tables"
  type = map(object({
    table_name = string
    group      = string
    backup     = bool
  }))

  default = {
    dev = {
      table_name = "devops-db-testing-50"
      group      = "devops-testing"
      backup     = false
    }

    staging = {
      table_name = "devops-db-staging-50"
      group      = "devops-staging"
      backup     = false
    }

    prod = {
      table_name = "devops-db-prod-50"
      group      = "devops-prod"
      backup     = false
    }
  }
}