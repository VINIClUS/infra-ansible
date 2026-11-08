resource "aws_ecs_cluster" "processor" {
  name = "${var.name_prefix}-processor"

  setting {
    name  = "containerInsights"
    value = "disabled"
  }
}

resource "aws_sfn_state_machine" "processor" {
  count = var.processor_active_unit_task_definition_arn == null ? 0 : 1

  name     = var.name_prefix
  type     = "STANDARD"
  role_arn = var.step_functions_role_arn
  definition = templatefile("${path.module}/state_machine.asl.json", {
    cluster_arn         = aws_ecs_cluster.processor.arn
    task_definition_arn = var.processor_active_unit_task_definition_arn
    public_subnet_ids   = jsonencode(sort(distinct(var.public_subnet_ids)))
    security_group_id   = var.security_group_id
  })
}

locals {
  run_task_enabled = (
    var.image_digest != null || length(var.processor_retained_unit_task_definition_arns) > 0
  )
  run_task_resources = sort(setunion(
    [for key, definition in aws_ecs_task_definition.processor : definition.arn if key == "unit"],
    var.processor_retained_unit_task_definition_arns,
  ))
}

resource "aws_iam_role_policy" "step_functions_ecs" {
  count = var.enable_step_functions_iam ? 1 : 0

  name = "${var.name_prefix}-step-functions-ecs"
  role = var.step_functions_role_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks", "ecs:StopTask"]
        Resource = "*"
      }],
      [for resources in [local.run_task_resources] : {
        Effect   = "Allow"
        Action   = "ecs:RunTask"
        Resource = resources
      } if local.run_task_enabled],
    )
  })
}
