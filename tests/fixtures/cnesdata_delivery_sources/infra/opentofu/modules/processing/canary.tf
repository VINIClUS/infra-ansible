locals {
  canary_count           = var.canary_storage_enabled ? 1 : 0
  canary_name            = "${var.name_prefix}-canary"
  canary_retention_days  = 1
  canary_expiration_days = 2
  canary_index_names     = [for position in range(1, 7) : "gsi${position}"]
  canary_audit_task_definition_arn = one([
    for mode, definition in aws_ecs_task_definition.processor : definition.arn if mode == "audit"
  ])
}

# Schema copy of modules/control-plane (parity pinned by tests); a nested module call would escape
# the package when this module is sourced by absolute path.
resource "aws_dynamodb_table" "canary" {
  count = local.canary_count

  name                        = local.canary_name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true

  dynamic "attribute" {
    for_each = toset(concat(["pk", "sk"], flatten([
      for index in local.canary_index_names : ["${index}pk", "${index}sk"]
    ])))
    content {
      name = attribute.value
      type = "S"
    }
  }

  dynamic "global_secondary_index" {
    for_each = toset(local.canary_index_names)
    content {
      name            = global_secondary_index.value
      projection_type = "ALL"

      key_schema {
        attribute_name = "${global_secondary_index.value}pk"
        key_type       = "HASH"
      }

      key_schema {
        attribute_name = "${global_secondary_index.value}sk"
        key_type       = "RANGE"
      }

      on_demand_throughput {
        max_read_request_units  = 100
        max_write_request_units = 25
      }
    }
  }

  on_demand_throughput {
    max_read_request_units  = 100
    max_write_request_units = 25
  }

  point_in_time_recovery {
    enabled                 = true
    recovery_period_in_days = 35
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "canary" {
  count = local.canary_count

  bucket              = local.canary_name
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "canary" {
  count = local.canary_count

  bucket                  = aws_s3_bucket.canary[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "canary" {
  count = local.canary_count

  bucket = aws_s3_bucket.canary[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "canary" {
  count = local.canary_count

  bucket = aws_s3_bucket.canary[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 by design, same as the audit bucket: no KMS request charges or key-policy coupling.
#trivy:ignore:AVD-AWS-0132:exp:2027-04-11
resource "aws_s3_bucket_server_side_encryption_configuration" "canary" {
  count = local.canary_count

  bucket = aws_s3_bucket.canary[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "canary" {
  count = local.canary_count

  bucket              = aws_s3_bucket.canary[0].id
  object_lock_enabled = "Enabled"

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = local.canary_retention_days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "canary" {
  count = local.canary_count

  bucket = aws_s3_bucket.canary[0].id

  rule {
    id     = "expire-audit"
    status = "Enabled"

    filter {
      prefix = "audit/"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }

    expiration {
      days = local.canary_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = local.canary_expiration_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.canary]
}

resource "aws_s3_bucket_policy" "canary" {
  count = local.canary_count

  bucket = aws_s3_bucket.canary[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.canary[0].arn, "${aws_s3_bucket.canary[0].arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.canary]
}

resource "aws_iam_role_policy" "canary_verifier_run_task" {
  count = var.canary_verifier_role_id == null ? 0 : 1

  name = "${var.name_prefix}-canary-verifier-run-task"
  role = var.canary_verifier_role_id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "ecs:RunTask"
      Resource  = local.canary_audit_task_definition_arn
      Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.processor.arn } }
    }]
  })

  lifecycle {
    precondition {
      condition     = var.image_digest != null
      error_message = "canary_run_task=requires_image_digest"
    }
  }
}
