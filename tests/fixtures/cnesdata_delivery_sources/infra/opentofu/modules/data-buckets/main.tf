terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

locals {
  retained_data_prefixes = ["raw", "normalized", "reconciliation", "serving"]
  tmp_prefix             = "tmp"
  data_prefixes          = concat(local.retained_data_prefixes, [local.tmp_prefix])
  audit_prefix           = "audit"
  audit_default_retention = {
    mode = "COMPLIANCE"
    days = 365
  }
  serving_cors = {
    origin          = "https://cnesdata.com.br"
    methods         = ["GET", "HEAD"]
    max_age_seconds = 300
  }
  abort_incomplete_multipart_days = 1
  # tmp/ holds unit attempt outputs that later waves and publication read, so it must outlast the
  # pauses built into the product: the monthly StartExecution quota defers a start to the next UTC
  # month (31 days at most) and a cost freeze lasts until the reviewed cost-clear. 35 days cover a
  # whole quota deferral plus the 3600 s lease; a cost freeze must be cleared within that window,
  # or paused runs lose their tmp/ outputs.
  tmp_expiration_days            = 35
  tmp_noncurrent_expiration_days = 1
}

resource "aws_s3_bucket" "data" {
  bucket = var.bucket_names.data

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "audit" {
  bucket              = var.bucket_names.audit
  object_lock_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 by design (deployment spec section 9 principle): no KMS request charges, no coupling to
# the shared key policy, and COMPLIANCE-locked audit objects never depend on an external key.
#trivy:ignore:AVD-AWS-0132:exp:2027-04-11
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

#trivy:ignore:AVD-AWS-0132:exp:2027-04-11
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket              = aws_s3_bucket.audit.id
  object_lock_enabled = "Enabled"

  rule {
    default_retention {
      mode = local.audit_default_retention.mode
      days = local.audit_default_retention.days
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  dynamic "rule" {
    for_each = local.retained_data_prefixes
    content {
      id     = "retain-${rule.value}"
      status = "Enabled"

      filter {
        prefix = "${rule.value}/"
      }

      abort_incomplete_multipart_upload {
        days_after_initiation = local.abort_incomplete_multipart_days
      }
    }
  }

  rule {
    id     = "expire-${local.tmp_prefix}"
    status = "Enabled"

    filter {
      prefix = "${local.tmp_prefix}/"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = local.abort_incomplete_multipart_days
    }

    expiration {
      days = local.tmp_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = local.tmp_noncurrent_expiration_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "retain-${local.audit_prefix}"
    status = "Enabled"

    filter {
      prefix = "${local.audit_prefix}/"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = local.abort_incomplete_multipart_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_cors_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  cors_rule {
    allowed_origins = [local.serving_cors.origin]
    allowed_methods = local.serving_cors.methods
    max_age_seconds = local.serving_cors.max_age_seconds
  }
}
