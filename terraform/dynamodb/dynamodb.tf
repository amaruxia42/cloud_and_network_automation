resource "aws_dynamodb_table" "nautilus_dyndb" {
  for_each       = var.dynamodb_table_tags
  name           = each.value.table_name
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "TestTableHashKey"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }
  tags = merge({
    Name        = each.value.table_name
    Environment = title(each.key)
  })
}