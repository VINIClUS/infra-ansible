terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    archive = {
      source = "hashicorp/archive"
    }
  }
}

locals {
  region                   = "us-east-2"
  workgroup_name           = "${var.name_prefix}-operator"
  cutoff_name              = "${var.name_prefix}-athena-cutoff"
  results_bucket           = "${var.name_prefix}-athena-results"
  per_query_cutoff_bytes   = 5000000000
  window_bytes             = 2000000000
  window_seconds           = 86400
  windows_per_month        = 31
  overshoot_queries        = 4
  crossing_queries         = 1
  billed_queries_per_month = 1000
  per_query_overhead_bytes = 10485760
  detection_latency_s      = 300
  month_limit_bytes        = 100000000000
  results_expiration       = 7
  abort_multipart_days     = 1

  workgroup_arn = format(
    "arn:aws:athena:%s:%s:workgroup/%s", local.region, var.account_id, local.workgroup_name,
  )
  alarm_arn = format(
    "arn:aws:cloudwatch:%s:%s:alarm:%s", local.region, var.account_id, local.cutoff_name,
  )
  cutoff_topic_arn = format(
    "arn:aws:sns:%s:%s:%s", local.region, var.account_id, aws_sns_topic.cutoff.name,
  )
  cutoff_role_arn = format(
    "arn:aws:iam::%s:role/%s", var.account_id, aws_iam_role.cutoff.name,
  )
  cutoff_function_arn = format(
    "arn:aws:lambda:%s:%s:function:%s", local.region, var.account_id,
    aws_lambda_function.cutoff.function_name,
  )
  states = { succeeded = "SUCCEEDED", failed = "FAILED", canceled = "CANCELED" }
}

resource "aws_s3_bucket" "results" {
  bucket        = local.results_bucket
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SSE-S3 by design: query results are short-lived (7 days) and an Athena result location with a
# customer key would couple the operator path to the externally owned key policy.
#trivy:ignore:AVD-AWS-0132:exp:2027-04-11
resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "results" {
  bucket = aws_s3_bucket.results.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = ["arn:aws:s3:::${local.results_bucket}", "arn:aws:s3:::${local.results_bucket}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.results]
}

resource "aws_s3_bucket_lifecycle_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    id     = "expire-results"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = local.results_expiration
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = local.abort_multipart_days
    }
  }
}

resource "aws_athena_workgroup" "operator" {
  name          = local.workgroup_name
  state         = "ENABLED"
  force_destroy = false

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    requester_pays_enabled             = false
    bytes_scanned_cutoff_per_query     = local.per_query_cutoff_bytes

    result_configuration {
      output_location       = "s3://${local.results_bucket}/results/"
      expected_bucket_owner = var.account_id

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  # The cutoff Lambda disables the workgroup; an apply must not re-enable it (manual operator step).
  lifecycle {
    ignore_changes = [state]
  }
}

# The CloudWatch alarm service cannot publish to a topic encrypted with the AWS-managed aws/sns key
# and the shared customer key policy is externally owned; alarm payloads carry no secret.
#trivy:ignore:AVD-AWS-0095:exp:2027-04-11
resource "aws_sns_topic" "cutoff" {
  name = local.cutoff_name
}

resource "aws_sns_topic_policy" "cutoff" {
  arn = local.cutoff_topic_arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCutoffAlarmPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = local.cutoff_topic_arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
          ArnEquals    = { "aws:SourceArn" = local.alarm_arn }
        }
      },
      {
        Sid       = "AllowSharedBudgetPublish"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = local.cutoff_topic_arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
          ArnEquals    = { "aws:SourceArn" = var.budget_arn }
        }
      },
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "cutoff" {
  alarm_name          = local.cutoff_name
  alarm_description   = "Athena DML bytes reached the 1-day window; disables the workgroup."
  evaluation_periods  = 1
  threshold           = local.window_bytes
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.cutoff_topic_arn]

  metric_query {
    id          = "total"
    expression  = "FILL(succeeded, 0) + FILL(failed, 0) + FILL(canceled, 0)"
    label       = "ProcessedBytes DML"
    return_data = true
  }

  dynamic "metric_query" {
    for_each = local.states

    content {
      id          = metric_query.key
      return_data = false

      metric {
        namespace   = "AWS/Athena"
        metric_name = "ProcessedBytes"
        period      = local.window_seconds
        stat        = "Sum"
        dimensions = {
          QueryState = metric_query.value
          QueryType  = "DML"
          WorkGroup  = aws_athena_workgroup.operator.name
        }
      }
    }
  }
}

data "archive_file" "cutoff" {
  type        = "zip"
  source_file = "${path.module}/cutoff_handler.py"
  output_path = "${path.root}/.terraform/athena-cutoff.zip"
}

resource "aws_iam_role" "cutoff" {
  name = local.cutoff_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "cutoff" {
  name = "${local.cutoff_name}-workgroup"
  role = aws_iam_role.cutoff.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "athena:UpdateWorkGroup"
      Resource = local.workgroup_arn
    }]
  })
}

resource "aws_lambda_function" "cutoff" {
  function_name    = local.cutoff_name
  role             = local.cutoff_role_arn
  runtime          = "python3.13"
  handler          = "cutoff_handler.handler"
  timeout          = 30
  memory_size      = 128
  filename         = data.archive_file.cutoff.output_path
  source_code_hash = data.archive_file.cutoff.output_base64sha256

  environment {
    variables = { ATHENA_WORKGROUP = aws_athena_workgroup.operator.name }
  }
}

resource "aws_lambda_permission" "cutoff" {
  statement_id  = "AllowCutoffTopicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cutoff.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = local.cutoff_topic_arn
}

resource "aws_sns_topic_subscription" "cutoff" {
  topic_arn = local.cutoff_topic_arn
  protocol  = "lambda"
  endpoint  = local.cutoff_function_arn
}
