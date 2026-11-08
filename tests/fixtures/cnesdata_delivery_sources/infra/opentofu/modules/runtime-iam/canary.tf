locals {
  canary                      = var.canary_release
  canary_count                = var.canary_release == null ? 0 : 1
  canary_max_session_duration = 3600
  canary_event_id = (
    var.canary_release == null ? null : "canary-${local.canary.release_id}"
  )
  canary_session_names = var.canary_release == null ? null : {
    seeder   = "canary-seeder-${local.canary.release_id}"
    verifier = "canary-verifier-${local.canary.release_id}"
    operator = "promotion-fence-${local.canary.release_id}"
  }
  canary_object_arns = var.canary_release == null ? null : [
    "${local.canary.bucket_arn}/audit/.event-id/${local.canary_event_id}.json",
    "${local.canary.bucket_arn}/audit/*/*/*/*/${local.canary_event_id}.json",
  ]
  canary_tags = var.canary_release == null ? {} : { ReleaseId = local.canary.release_id }
  canary_principal_trust = {
    for name, session in(local.canary_session_names == null ? {} : local.canary_session_names) :
    name => jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { AWS = local.canary.trusted_principal_arn }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "sts:RoleSessionName" = session } }
      }]
    })
  }
}

resource "aws_iam_role" "canary_task" {
  count = local.canary_count

  name                 = "${var.name_prefix}-canary-task"
  assume_role_policy   = local.ecs_trust_policy
  max_session_duration = local.canary_max_session_duration
  tags                 = local.canary_tags
}

resource "aws_iam_role" "canary_execution" {
  count = local.canary_count

  name                 = "${var.name_prefix}-canary-execution"
  assume_role_policy   = local.ecs_trust_policy
  max_session_duration = local.canary_max_session_duration
  tags                 = local.canary_tags
}

resource "aws_iam_role" "canary_seeder" {
  count = local.canary_count

  name                 = "${var.name_prefix}-canary-seeder"
  assume_role_policy   = local.canary_principal_trust["seeder"]
  max_session_duration = local.canary_max_session_duration
  tags                 = local.canary_tags
}

resource "aws_iam_role" "canary_verifier" {
  count = local.canary_count

  name                 = "${var.name_prefix}-canary-verifier"
  assume_role_policy   = local.canary_principal_trust["verifier"]
  max_session_duration = local.canary_max_session_duration
  tags                 = local.canary_tags
}

resource "aws_iam_role_policy" "canary_task" {
  count = local.canary_count

  name = "${var.name_prefix}-canary-task-runtime"
  role = aws_iam_role.canary_task[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:Query"
        Resource = local.canary.index_arn
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["OUTBOX#PENDING"] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = local.canary.table_arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = ["TENANT#_GLOBAL", "OUTBOX#CURSOR"]
          }
          Null = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketObjectLockConfiguration"
        Resource = local.canary.bucket_arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject", "s3:PutObjectRetention", "s3:GetObject", "s3:GetObjectRetention",
        ]
        Resource = "${local.canary.bucket_arn}/audit/*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "canary_execution" {
  count = local.canary_count

  name = "${var.name_prefix}-canary-pull-logs"
  role = aws_iam_role.canary_execution[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchCheckLayerAvailability",
        ]
        Resource = var.repository_arn
      },
      {
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${trimsuffix(var.log_group_arn, ":*")}:log-stream:*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "canary_seeder" {
  count = local.canary_count

  name = "${var.name_prefix}-canary-seeder-put"
  role = aws_iam_role.canary_seeder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "dynamodb:PutItem"
      Resource = local.canary.table_arn
      Condition = {
        "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["TENANT#_GLOBAL"] }
        Null                        = { "dynamodb:LeadingKeys" = "false" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "canary_verifier" {
  count = local.canary_count

  name = "${var.name_prefix}-canary-verifier-read"
  role = aws_iam_role.canary_verifier[0].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:Query"
        Resource = local.canary.index_arn
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["OUTBOX#PENDING"] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = "dynamodb:GetItem"
        Resource = local.canary.table_arn
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["TENANT#_GLOBAL"] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectRetention"]
        Resource = local.canary_object_arns
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.canary_task[0].arn,
          aws_iam_role.canary_execution[0].arn,
        ]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      },
    ]
  })
}
