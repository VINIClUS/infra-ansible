output "table_name" {
  description = "Control-plane table name."
  value       = aws_dynamodb_table.control_plane.name
}

output "table_arn" {
  description = "Control-plane table ARN for runtime IAM policies."
  value       = aws_dynamodb_table.control_plane.arn
}

output "index_arns" {
  description = "Exact ARN of each global secondary index, keyed by index name."
  value = {
    for name in keys(local.global_secondary_indexes) :
    name => "${aws_dynamodb_table.control_plane.arn}/index/${name}"
  }
}
