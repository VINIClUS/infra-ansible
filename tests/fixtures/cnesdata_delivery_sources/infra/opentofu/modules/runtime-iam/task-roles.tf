locals {
  ecs_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.account_id }
      }
    }]
  })
}

resource "aws_iam_role" "task" {
  for_each = toset(["unit", "recovery", "audit"])

  name               = "${var.name_prefix}-processor-${each.key}"
  assume_role_policy = local.ecs_trust_policy
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-processor-execution"
  assume_role_policy = local.ecs_trust_policy
}

resource "aws_iam_role_policy" "execution" {
  name = "${var.name_prefix}-processor-pull-logs"
  role = aws_iam_role.execution.name
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

locals {
  data_prefixes    = ["raw/*", "tmp/*", "normalized/*", "reconciliation/*", "serving/*"]
  publish_prefixes = ["tmp/*", "normalized/*", "reconciliation/*", "serving/*"]
  runtime_shared_statements = var.runtime_grants == null ? null : [
    {
      Effect   = "Allow"
      Action   = ["states:DescribeStateMachine", "states:StartExecution"]
      Resource = var.state_machine_arn
    },
    {
      Effect   = "Allow"
      Action   = ["states:DescribeExecution", "states:StopExecution"]
      Resource = "${replace(var.state_machine_arn, ":stateMachine:", ":execution:")}:*"
    },
    {
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem", "dynamodb:Query", "dynamodb:ConditionCheckItem",
        "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem",
      ]
      Resource = var.runtime_grants.table_arn
      Condition = {
        "ForAllValues:StringLike" = {
          "dynamodb:LeadingKeys" = [
            "TENANT#*", "TENANT#*#RUN#*", "TENANT#_GLOBAL",
            "ENV#prod#FENCE", "ENV#prod#SEMAPHORE",
          ]
        }
        Null = { "dynamodb:LeadingKeys" = "false" }
      }
    },
    {
      Effect   = "Allow"
      Action   = "dynamodb:UpdateItem"
      Resource = var.runtime_grants.table_arn
      Condition = {
        "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["ENV#prod#ATTEMPTS"] }
        Null                        = { "dynamodb:LeadingKeys" = "false" }
      }
    },
  ]
  runtime_statements = var.runtime_grants == null ? null : {
    unit = concat(local.runtime_shared_statements, [
      {
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = [
          for prefix in local.data_prefixes : "${var.runtime_grants.data_bucket_arn}/${prefix}"
        ]
      },
      {
        Effect = "Allow"
        Action = "s3:PutObject"
        Resource = [
          for prefix in local.publish_prefixes : "${var.runtime_grants.data_bucket_arn}/${prefix}"
        ]
      },
      {
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = var.runtime_grants.data_bucket_arn
        Condition = { StringLike = { "s3:prefix" = local.data_prefixes } }
      },
    ])
    recovery = concat(local.runtime_shared_statements, [
      {
        Effect   = "Allow"
        Action   = "dynamodb:Query"
        Resource = var.runtime_grants.index_arns.gsi4
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["RUN_RECOVERABLE"] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject"]
        Resource = [
          for prefix in local.publish_prefixes : "${var.runtime_grants.data_bucket_arn}/${prefix}"
        ]
      },
      {
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = var.runtime_grants.data_bucket_arn
        Condition = { StringLike = { "s3:prefix" = local.publish_prefixes } }
      },
    ])
    audit = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:Query"
        Resource = var.runtime_grants.index_arns.gsi6
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["OUTBOX#PENDING"] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = var.runtime_grants.table_arn
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
        Resource = var.runtime_grants.audit_bucket_arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject", "s3:PutObjectRetention", "s3:GetObject", "s3:GetObjectRetention",
        ]
        Resource = "${var.runtime_grants.audit_bucket_arn}/audit/*"
      },
    ]
  }
  api_data_statements = var.runtime_grants == null ? null : [
    {
      Effect   = "Allow"
      Action   = "dynamodb:Query"
      Resource = var.runtime_grants.index_arns.gsi1
      Condition = {
        "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["USER#*"] }
        Null                      = { "dynamodb:LeadingKeys" = "false" }
      }
    },
    {
      Effect   = "Allow"
      Action   = "dynamodb:GetItem"
      Resource = var.runtime_grants.table_arn
      Condition = {
        "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["TENANT#*"] }
        Null                      = { "dynamodb:LeadingKeys" = "false" }
      }
    },
    {
      Effect = "Allow"
      Action = "s3:GetObject"
      Resource = [
        "${var.runtime_grants.data_bucket_arn}/reconciliation/*",
        "${var.runtime_grants.data_bucket_arn}/serving/*",
      ]
    },
    {
      Effect   = "Allow"
      Action   = "s3:ListBucket"
      Resource = var.runtime_grants.data_bucket_arn
      Condition = {
        StringLike = { "s3:prefix" = ["reconciliation/*", "serving/*"] }
      }
    },
  ]
  api_sfn_statements = var.state_machine_arn == null ? null : [
    {
      Effect   = "Allow"
      Action   = ["states:DescribeStateMachine", "states:StartExecution"]
      Resource = var.state_machine_arn
    },
    {
      Effect   = "Allow"
      Action   = ["states:DescribeExecution", "states:StopExecution"]
      Resource = "${replace(var.state_machine_arn, ":stateMachine:", ":execution:")}:*"
    },
  ]
}

resource "aws_iam_role_policy" "runtime" {
  for_each = var.runtime_grants == null ? toset([]) : toset(["unit", "recovery", "audit"])

  name = "${var.name_prefix}-processor-${each.key}-runtime"
  role = aws_iam_role.task[each.key].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.runtime_statements[each.key]
  })
}

resource "aws_iam_role_policy" "api" {
  count = var.runtime_grants == null ? 0 : 1

  name = "${var.name_prefix}-api-runtime"
  role = try(element(reverse(split("/", var.runtime_grants.api_role_arn)), 0), null)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      local.api_data_statements,
      [for statement in local.api_sfn_statements : statement if var.api_step_functions_enabled],
    )
  })
}
