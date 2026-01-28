
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "test_ec2s" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"

  for_each = var.test_ec2

  tags = merge({
    Name        = each.value.EC2_name
    Environment = title(each.key)
  })
}

