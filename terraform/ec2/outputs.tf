
output "instances" {
  description = "EC2 instance IDs"
  value = {
    for k, v in aws_instance.test_ec2s :
    k => v.id
  }
}

output "ami_id" {
  value = data.aws_ami.amazon_linux.id
}