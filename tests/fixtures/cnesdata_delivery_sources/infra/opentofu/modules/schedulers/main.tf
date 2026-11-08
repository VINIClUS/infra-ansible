locals {
  region = "us-east-2"

  modes = {
    recovery = { revision = var.recovery_task_definition_arn, freeze_target = true }
    audit    = { revision = var.audit_task_definition_arn, freeze_target = false }
  }

  scheduled = { for mode, spec in local.modes : mode => spec if spec.revision != null }

  cadence_minutes         = 30
  billed_minutes_per_run  = 2
  runs_per_30_days        = 30 * 24 * 60 / local.cadence_minutes
  hours_per_mode_30_days  = local.runs_per_30_days * local.billed_minutes_per_run / 60
  monthly_task_hour_limit = 100

  schedule_group_arns_by_mode = {
    for mode in keys(local.modes) : mode => format(
      "arn:aws:scheduler:%s:%s:schedule-group/%s-%s",
      local.region, var.account_id, var.name_prefix, mode,
    )
  }

  role_arns_by_mode = {
    for mode in keys(local.modes) : mode => format(
      "arn:aws:iam::%s:role/%s-scheduler-%s", var.account_id, var.name_prefix, mode,
    )
  }

  task_events = {
    recovery_failed = {
      mode = "recovery"
      detail = {
        "$or" = [
          { containers = { exitCode = [{ "anything-but" = 0 }] } },
          { stopCode = ["TaskFailedToStart"] },
        ]
      }
    }
    audit_failed = {
      mode = "audit"
      detail = {
        "$or" = [
          { containers = { exitCode = [{ "anything-but" = 0 }] } },
          { stopCode = ["TaskFailedToStart"] },
        ]
      }
    }
    audit_succeeded = {
      mode   = "audit"
      detail = { containers = { exitCode = [0] } }
    }
  }
  task_events_scheduled = {
    for name, event in local.task_events : name => event if contains(keys(local.scheduled), event.mode)
  }
}

resource "aws_scheduler_schedule_group" "mode" {
  for_each = local.scheduled

  name = "${var.name_prefix}-${each.key}"
}

resource "aws_scheduler_schedule" "mode" {
  for_each = local.scheduled

  name                = "${var.name_prefix}-${each.key}"
  group_name          = aws_scheduler_schedule_group.mode[each.key].name
  schedule_expression = "rate(${local.cadence_minutes} minutes)"
  state               = "ENABLED"
  depends_on          = [aws_iam_role_policy.run]

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = var.cluster_arn
    role_arn = local.role_arns_by_mode[each.key]

    retry_policy {
      maximum_retry_attempts       = 0
      maximum_event_age_in_seconds = 900
    }

    ecs_parameters {
      task_definition_arn     = each.value.revision
      launch_type             = "FARGATE"
      task_count              = 1
      enable_ecs_managed_tags = false
      enable_execute_command  = false

      network_configuration {
        assign_public_ip = true
        security_groups  = [var.security_group_id]
        subnets          = sort(distinct(var.public_subnet_ids))
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "task_outcome" {
  for_each = local.task_events_scheduled

  name = "${var.name_prefix}-scheduler-${replace(each.key, "_", "-")}"
  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Task State Change"]
    detail = merge(each.value.detail, {
      lastStatus = ["STOPPED"]
      clusterArn = [var.cluster_arn]
      group      = ["family:${var.name_prefix}-processor-${each.value.mode}"]
    })
  })
}

resource "aws_cloudwatch_metric_alarm" "repeated_failure" {
  for_each = { for mode in keys(local.scheduled) : mode => "${mode}_failed" }

  alarm_name          = "${var.name_prefix}-scheduler-${each.key}-repeated-failure"
  alarm_description   = "Two consecutive hourly windows with a failed ${each.key} task."
  namespace           = "AWS/Events"
  metric_name         = "TriggeredRules"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.task_outcome[each.value].name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "lost_invocation" {
  for_each = local.scheduled

  alarm_name          = "${var.name_prefix}-scheduler-${each.key}-lost-invocation"
  alarm_description   = "A ${each.key} invocation failed to start or was dropped as expired."
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_actions

  metric_query {
    id          = "lost"
    expression  = "target_errors + dropped"
    label       = "lost invocations"
    return_data = true
  }

  dynamic "metric_query" {
    for_each = { target_errors = "TargetErrorCount", dropped = "InvocationDroppedCount" }

    content {
      id = metric_query.key

      metric {
        namespace   = "AWS/Scheduler"
        metric_name = metric_query.value
        dimensions  = { ScheduleGroup = aws_scheduler_schedule_group.mode[each.key].name }
        period      = 1800
        stat        = "Sum"
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "outbox_backlog" {
  count = contains(keys(local.scheduled), "audit") ? 1 : 0

  alarm_name          = "${var.name_prefix}-scheduler-audit-outbox-backlog"
  alarm_description   = "No successful dispatch pass in two consecutive hourly windows."
  namespace           = "AWS/Events"
  metric_name         = "TriggeredRules"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.task_outcome["audit_succeeded"].name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = var.alarm_actions
}
