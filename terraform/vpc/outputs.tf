output "test_vpc_with_logs" {
    value = aws_vpc.test_vpc_with_logs.id
}

output "test_vpc_without_logs" {
    value = aws_vpc.test_vpc_without_logs.id
}

output "test_vpc_with_logs_arn" {
    value = aws_vpc.test_vpc_with_logs.cidr_block
}

output "test_vpc_without_logs_arn" {
    value = aws_vpc.test_vpc_without_logs.cidr_block
}