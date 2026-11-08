resource "aws_iam_role" "step_functions" {
  count = var.state_machine_arn == null ? 0 : 1

  name = "${var.name_prefix}-step-functions"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.account_id
          "aws:SourceArn"     = var.state_machine_arn
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "step_functions" {
  count = var.runtime_grants == null ? 0 : 1

  name = "${var.name_prefix}-step-functions-common"
  role = aws_iam_role.step_functions[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = [aws_iam_role.task["unit"].arn, aws_iam_role.execution.arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
      {
        Effect = "Allow"
        Action = ["events:PutTargets", "events:PutRule", "events:DescribeRule"]
        Resource = format(
          "arn:aws:events:us-east-2:%s:rule/StepFunctionsGetEventsForECSTaskRule",
          var.account_id,
        )
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:CreateLogStream",
          "logs:PutLogEvents", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
        ]
        Resource = "*"
      },
    ]
  })
}
