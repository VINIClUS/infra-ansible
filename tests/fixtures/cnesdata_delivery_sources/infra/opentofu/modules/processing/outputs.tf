output "task_definition_arns" {
  description = "Exact registered task definition revision ARNs keyed by processor mode."
  value       = { for mode, task in aws_ecs_task_definition.processor : mode => task.arn }
}

output "processor_container_name" {
  description = "Container name shared by all registered processor task definitions."
  value       = "processor"
}

output "cluster_arn" {
  description = "Own ECS processor cluster ARN."
  value       = aws_ecs_cluster.processor.arn
}

output "state_machine_arn" {
  description = "Active Standard state-machine ARN, or null during bootstrap."
  value       = one(aws_sfn_state_machine.processor[*].arn)
}

output "canary_table_name" {
  description = "Canary table name, or null while canary storage is disabled."
  value       = one(aws_dynamodb_table.canary[*].name)
}

output "canary_table_arn" {
  description = "Canary table ARN, or null while canary storage is disabled."
  value       = one(aws_dynamodb_table.canary[*].arn)
}

output "canary_gsi6_arn" {
  description = "Canary gsi6 index ARN, or null while canary storage is disabled."
  value       = one([for table in aws_dynamodb_table.canary : "${table.arn}/index/gsi6"])
}

output "canary_bucket_name" {
  description = "Canary bucket name, or null while canary storage is disabled."
  value       = one(aws_s3_bucket.canary[*].bucket)
}

output "canary_bucket_arn" {
  description = "Canary bucket ARN, or null while canary storage is disabled."
  value       = one(aws_s3_bucket.canary[*].arn)
}

output "canary_retention_days" {
  description = "Canary Object Lock retention days for AWS_AUDIT_RETENTION_DAYS, or null."
  value       = var.canary_storage_enabled ? local.canary_retention_days : null
}
