variable "test_ec2" {
  description = "EC2 for audit testing"
  type = map(object({
    EC2_name = string
    Group    = string
  }))

  default = {
    dev = {
      EC2_name = "Captain America"
      Group    = "Avengers"
      backup   = false
    }

    staging = {
      EC2_name = "Storm"
      Group    = "Uncanny X-men"
      backup   = false
    }

    prod = {
      EC2_name = "Spiderman"
      Group    = "Individual"
      backup   = false
    }
  }
}