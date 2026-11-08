output "schedule_arns" {
  description = "Schedule ARNs keyed by mode; empty until a revision is supplied."
  value       = { for mode, schedule in aws_scheduler_schedule.mode : mode => schedule.arn }
}

output "scheduler_role_arns" {
  description = "Scheduler execution role ARNs keyed by mode."
  value       = { for mode, role in aws_iam_role.scheduler : mode => role.arn }
}

output "scheduler_role_names" {
  description = "Scheduler execution role names keyed by mode."
  value       = { for mode, role in aws_iam_role.scheduler : mode => role.name }
}

output "freeze_target_role_names" {
  description = "Scheduler roles a cost freeze may restrict: recovery only."
  value       = [for mode, spec in local.modes : aws_iam_role.scheduler[mode].name if spec.freeze_target]
}

output "freeze_target_schedule_arns" {
  description = "Schedules a cost freeze may stop: recovery only."
  value = [
    for mode, spec in local.scheduled : aws_scheduler_schedule.mode[mode].arn if spec.freeze_target
  ]
}

output "freeze_excluded_role_names" {
  description = "Scheduler roles a cost freeze must not restrict: audit delivery continues."
  value       = [for mode, spec in local.modes : aws_iam_role.scheduler[mode].name if !spec.freeze_target]
}

output "task_hour_budget" {
  description = "Scheduled task-hours per 30 days; the limit is an alarm target, never a start gate."
  value = {
    monthly_limit_hours    = local.monthly_task_hour_limit
    recovery_hours         = local.hours_per_mode_30_days
    audit_hours            = local.hours_per_mode_30_days
    scheduled_hours        = 2 * local.hours_per_mode_30_days
    unit_reserve_hours     = local.monthly_task_hour_limit - 2 * local.hours_per_mode_30_days
    billed_minutes_per_run = local.billed_minutes_per_run
    cadence_minutes        = local.cadence_minutes
  }
}

output "alarm_names" {
  description = "Alarm names for the cost and alerting module."
  value = {
    repeated_failure = { for mode, alarm in aws_cloudwatch_metric_alarm.repeated_failure : mode => alarm.alarm_name }
    lost_invocation  = { for mode, alarm in aws_cloudwatch_metric_alarm.lost_invocation : mode => alarm.alarm_name }
    outbox_backlog   = one(aws_cloudwatch_metric_alarm.outbox_backlog[*].alarm_name)
  }
}
