locals {
  commands = {
    unit     = []
    recovery = ["recover-once"]
    audit    = ["dispatch-outbox-once"]
  }

  common_environment = {
    PROFILE                 = "aws"
    AWS_PRODUCTION_POLICY   = "true"
    AWS_REGION              = "us-east-2"
    AWS_ENVIRONMENT         = "prod"
    AWS_CONTROL_PLANE_TABLE = var.control_plane_table
    BILLING_MODE            = "disabled"
    TMPDIR                  = "/tmp"
    PYTHONDONTWRITEBYTECODE = "1"
  }

  processor_environment = {
    AWS_DATA_BUCKET               = var.data_bucket
    AWS_STATE_MACHINE_ARN         = var.state_machine_arn
    AWS_PROCESSOR_CONTAINER_NAME  = "processor"
    AWS_PROCESSOR_MAX_CONCURRENCY = "1"
    AWS_PROCESSOR_LEASE_SECONDS   = "3600"
    AWS_PUBLIC_SUBNET_IDS         = join(",", sort(distinct(var.public_subnet_ids)))
    AWS_SECURITY_GROUP_ID         = var.security_group_id
  }

  environments = {
    unit = merge(local.common_environment, local.processor_environment)
    recovery = merge(local.common_environment, local.processor_environment, {
      AWS_PROCESSOR_RECOVERY_BATCH_SIZE = "100"
    })
    audit = merge(local.common_environment, {
      AWS_AUDIT_BUCKET         = var.audit_bucket
      AWS_AUDIT_RETENTION_DAYS = tostring(var.audit_retention_days)
    })
  }

  linux_parameters = {
    capabilities = {
      drop = ["ALL"]
    }
  }

  log_options = {
    for mode in keys(local.commands) : mode => {
      awslogs-group         = var.log_group_name
      awslogs-region        = "us-east-2"
      awslogs-stream-prefix = mode
    }
  }
}

resource "aws_ecs_task_definition" "processor" {
  for_each = var.image_digest == null ? toset([]) : toset(keys(local.commands))

  family                   = "${var.name_prefix}-processor-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arns[each.key]
  skip_destroy             = true
  track_latest             = false

  runtime_platform {
    cpu_architecture        = "X86_64"
    operating_system_family = "LINUX"
  }

  dynamic "volume" {
    for_each = toset(["tmp", "logs", "data"])
    content {
      name = volume.value
    }
  }

  container_definitions = jsonencode([{
    name                   = "processor"
    image                  = "${var.repository_uri}@${var.image_digest}"
    command                = local.commands[each.key]
    readonlyRootFilesystem = true
    user                   = "app"
    privileged             = false
    linuxParameters        = local.linux_parameters
    environment = [
      for name, value in local.environments[each.key] : { name = name, value = value }
    ]
    mountPoints = [
      for path in ["/tmp", "/logs", "/data"] : {
        containerPath = path
        sourceVolume  = trimprefix(path, "/")
        readOnly      = false
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options   = local.log_options[each.key]
    }
  }])
}
