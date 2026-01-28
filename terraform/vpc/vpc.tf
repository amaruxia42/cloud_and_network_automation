terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "us-east-1" # Set the AWS region to US East (N. Virginia)
}

# Common tags
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "SecurityTesting"
    ManagedBy   = "Terraform"
  }
}

# VPC 1 - WITH Flow Logs (should pass flow logs check)
resource "aws_vpc" "test_vpc_with_logs" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name         = "${var.project_name}-vpc-with-logs"
    TestScenario = "flow-logs-enabled"
  })
}

# VPC 2 - WITHOUT Flow Logs (should fail flow logs check)
resource "aws_vpc" "test_vpc_without_logs" {
  cidr_block           = "10.2.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name         = "${var.project_name}-vpc-without-logs"
    TestScenario = "flow-logs-disabled"
  })
}

# Subnets for testing
resource "aws_subnet" "test_subnet_1" {
  vpc_id     = aws_vpc.test_vpc_with_logs.id
  cidr_block = "10.1.1.0/24"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-subnet-1"
  })
}

resource "aws_subnet" "test_subnet_2" {
  vpc_id     = aws_vpc.test_vpc_without_logs.id
  cidr_block = "10.2.1.0/24"

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-subnet-2"
  })
}

#=====================================================
# VPC FLOW LOGS CONFIGURATION
#=====================================================

# IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_logs_role" {
  name = "${var.project_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# IAM policy for VPC Flow Logs
resource "aws_iam_role_policy" "flow_logs_policy" {
  name = "${var.project_name}-flow-logs-policy"
  role = aws_iam_role.flow_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Log Group for Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs/${var.project_name}"
  retention_in_days = 7

  tags = local.common_tags
}

# VPC Flow Logs for VPC 1 (WITH logs)
resource "aws_flow_log" "test_vpc_with_logs_flow" {
  iam_role_arn    = aws_iam_role.flow_logs_role.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.test_vpc_with_logs.id

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-flow-logs-enabled"
  })
}

#=====================================================
# SECURITY GROUPS FOR TESTING
#=====================================================

# Security Group 1: SECURE (should pass) - Restrictive access
resource "aws_security_group" "secure_sg" {
  name        = "${var.project_name}-secure-sg"
  description = "Secure security group - should pass checks"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # Allow HTTP only from specific CIDR
  ingress {
    description = "HTTP from specific network"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Allow HTTPS only from specific CIDR
  ingress {
    description = "HTTPS from specific network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Restrictive SSH access
  ingress {
    description = "SSH from bastion"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.1.1.100/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name           = "${var.project_name}-secure-sg"
    TestScenario   = "secure-configuration"
    ExpectedResult = "PASS"
  })
}

# Security Group 2: HIGH RISK SSH (should fail with High severity)
resource "aws_security_group" "high_risk_ssh_sg" {
  name        = "${var.project_name}-high-risk-ssh-sg"
  description = "High risk - SSH open to world"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # SSH open to the world - HIGH RISK
  ingress {
    description = "SSH from anywhere - HIGH RISK"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-high-risk-ssh-sg"
    TestScenario     = "ssh-open-to-world"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "High"
  })
}

# Security Group 3: HIGH RISK RDP (should fail with High severity)
resource "aws_security_group" "high_risk_rdp_sg" {
  name        = "${var.project_name}-high-risk-rdp-sg"
  description = "High risk - RDP open to world"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # RDP open to the world - HIGH RISK
  ingress {
    description = "RDP from anywhere - HIGH RISK"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-high-risk-rdp-sg"
    TestScenario     = "rdp-open-to-world"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "High"
  })
}

# Security Group 4: HIGH RISK DATABASE (should fail with High severity)
resource "aws_security_group" "high_risk_db_sg" {
  name        = "${var.project_name}-high-risk-db-sg"
  description = "High risk - Database ports open to world"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # MySQL open to the world - HIGH RISK
  ingress {
    description = "MySQL from anywhere - HIGH RISK"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SQL Server open to the world - HIGH RISK
  ingress {
    description = "SQL Server from anywhere - HIGH RISK"
    from_port   = 1433
    to_port     = 1433
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-high-risk-db-sg"
    TestScenario     = "database-open-to-world"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "High"
  })
}

# Security Group 5: LOW RISK WEB (should fail with Low severity)
resource "aws_security_group" "low_risk_web_sg" {
  name        = "${var.project_name}-low-risk-web-sg"
  description = "Low risk - Web ports open to world"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # HTTP open to the world - LOW RISK (expected for web servers)
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS open to the world - LOW RISK (expected for web servers)
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-low-risk-web-sg"
    TestScenario     = "web-open-to-world"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "Low"
  })
}

# Security Group 6: MODERATE RISK CUSTOM PORT (should fail with Moderate severity)
resource "aws_security_group" "moderate_risk_custom_sg" {
  name        = "${var.project_name}-moderate-risk-custom-sg"
  description = "Moderate risk - Custom port open to world"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # Custom port open to the world - MODERATE RISK
  ingress {
    description = "Custom application port from anywhere"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Another custom port
  ingress {
    description = "Another custom port from anywhere"
    from_port   = 9999
    to_port     = 9999
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-moderate-risk-custom-sg"
    TestScenario     = "custom-ports-open-to-world"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "Moderate"
  })
}

# Security Group 7: IPv6 RISK (should fail - IPv6 open access)
resource "aws_security_group" "ipv6_risk_sg" {
  name        = "${var.project_name}-ipv6-risk-sg"
  description = "IPv6 risk - SSH open to IPv6 world"
  vpc_id      = aws_vpc.test_vpc_with_logs.id

  # SSH open to IPv6 world - HIGH RISK
  ingress {
    description      = "SSH from IPv6 anywhere - HIGH RISK"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-ipv6-risk-sg"
    TestScenario     = "ipv6-ssh-open-to-world"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "High"
  })
}

# Security Group 8: MIXED RISK (multiple issues)
resource "aws_security_group" "mixed_risk_sg" {
  name        = "${var.project_name}-mixed-risk-sg"
  description = "Mixed risk - Multiple issues"
  vpc_id      = aws_vpc.test_vpc_without_logs.id

  # SSH open to world - HIGH RISK
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP open to world - LOW RISK
  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Custom port open to world - MODERATE RISK
  ingress {
    description = "Custom port from anywhere"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name             = "${var.project_name}-mixed-risk-sg"
    TestScenario     = "multiple-risks"
    ExpectedResult   = "FAIL"
    ExpectedSeverity = "High" # Highest severity among the rules
  })
}
