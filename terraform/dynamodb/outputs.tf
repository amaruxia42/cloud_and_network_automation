
output "table_names" {
  value = {
    for name, table_name in aws_dynamodb_table.nautilus_dyndb :
    name => table_name.name
  }
}