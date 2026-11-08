resource "aws_iam_role" "scheduler" {
  for_each = local.modes

  name = "${var.name_prefix}-scheduler-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.account_id
          "aws:SourceArn"     = local.schedule_group_arns_by_mode[each.key]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "run" {
  for_each = local.modes

  name = "${var.name_prefix}-scheduler-${each.key}-run"
  role = aws_iam_role.scheduler[each.key].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [for revision in [each.value.revision] : {
        Effect   = "Allow"
        Action   = "ecs:RunTask"
        Resource = revision
        Condition = {
          ArnEquals = { "ecs:cluster" = var.cluster_arn }
        }
      } if revision != null],
      [{
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = [var.task_role_arns[each.key], var.execution_role_arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      }],
    )
  })
}
