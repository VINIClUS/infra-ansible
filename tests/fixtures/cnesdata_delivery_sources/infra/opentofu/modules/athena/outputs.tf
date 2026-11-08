output "cutoff_contract" {
  description = "Athena cutoff contract: window, per-query cutoff, in-flight and billing bounds."
  value = {
    window_bytes             = local.window_bytes
    window_seconds           = local.window_seconds
    per_query_cutoff_bytes   = local.per_query_cutoff_bytes
    windows_per_month        = local.windows_per_month
    overshoot_queries        = local.overshoot_queries
    crossing_queries         = local.crossing_queries
    billed_queries_per_month = local.billed_queries_per_month
    per_query_overhead_bytes = local.per_query_overhead_bytes
    detection_latency_s      = local.detection_latency_s
    month_limit_bytes        = local.month_limit_bytes
  }
}

output "workgroup_name" {
  description = "Operator Athena workgroup name."
  value       = aws_athena_workgroup.operator.name
}

output "workgroup_arn" {
  description = "Operator Athena workgroup ARN."
  value       = local.workgroup_arn
}

output "cutoff_topic_arn" {
  description = "SNS topic that triggers the cutoff Lambda: the freeze hook for Athena."
  value       = local.cutoff_topic_arn
}

output "cutoff_topic_name" {
  description = "Cutoff SNS topic name."
  value       = aws_sns_topic.cutoff.name
}

output "cutoff_function_name" {
  description = "Cutoff Lambda function name."
  value       = aws_lambda_function.cutoff.function_name
}

output "cutoff_role_name" {
  description = "Cutoff Lambda role name, excluded from the cost freeze."
  value       = aws_iam_role.cutoff.name
}
