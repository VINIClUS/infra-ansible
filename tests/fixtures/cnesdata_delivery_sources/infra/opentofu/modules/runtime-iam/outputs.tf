output "execution_role_arn" {
  description = "Shared execution identity ARN for processor tasks."
  value       = aws_iam_role.execution.arn
}

output "execution_role_name" {
  description = "Shared execution identity name for processor tasks."
  value       = aws_iam_role.execution.name
}

output "task_role_arns" {
  description = "Initially policy-free task identity ARNs by processor mode."
  value       = { for mode, role in aws_iam_role.task : mode => role.arn }
}

output "task_role_names" {
  description = "Initially policy-free task identity names by processor mode."
  value       = { for mode, role in aws_iam_role.task : mode => role.name }
}

output "step_functions_role_id" {
  description = "Step Functions role ID, or null for the base module."
  value       = one(aws_iam_role.step_functions[*].id)
}

output "step_functions_role_arn" {
  description = "Step Functions role ARN, or null for the base module."
  value       = one(aws_iam_role.step_functions[*].arn)
}

output "canary_task_role_arn" {
  description = "Canary task role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_task[*].arn)
}

output "canary_execution_role_arn" {
  description = "Canary execution role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_execution[*].arn)
}

output "canary_seeder_role_arn" {
  description = "Canary seeder role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_seeder[*].arn)
}

output "canary_verifier_role_arn" {
  description = "Canary verifier role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_verifier[*].arn)
}

output "canary_verifier_role_id" {
  description = "Canary verifier role name for the processing RunTask grant, or null."
  value       = one(aws_iam_role.canary_verifier[*].name)
}

output "promotion_fence_operator_role_arn" {
  description = "Promotion fence operator role ARN, or null without a release activation."
  value       = one(aws_iam_role.promotion_fence_operator[*].arn)
}

output "canary_session_names" {
  description = "Release-bound role session names required by the canary trust policies."
  value       = local.canary_session_names
}

output "canary_event_id" {
  description = "Release-bound canary event ID, or null without a release activation."
  value       = local.canary_event_id
}

output "canary_object_arns" {
  description = "Release-bound canary audit object ARNs read by the verifier."
  value       = local.canary_object_arns
}

output "canary_max_session_duration" {
  description = "Maximum session seconds of every canary and promotion role."
  value       = local.canary_max_session_duration
}
