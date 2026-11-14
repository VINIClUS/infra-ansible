locals {
  evidence_bucket_arn = var.evidence_enabled ? "arn:aws:s3:::${var.evidence_bucket_name}" : null
}

resource "aws_kms_key" "evidence" {
  count                              = var.evidence_enabled ? 1 : 0
  description                        = "CnesData delivery evidence cipher key"
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  is_enabled                         = true
  enable_key_rotation                = true
  multi_region                       = false
  deletion_window_in_days            = 30
  bypass_policy_lockout_safety_check = false
  tags                               = var.tags
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.evidence_bucket_name != null
      error_message = "evidence_bucket_name required when evidence_enabled=true."
    }
  }
}

resource "aws_kms_alias" "evidence" {
  count         = var.evidence_enabled ? 1 : 0
  name          = "alias/cnesdata-delivery-evidence"
  target_key_id = aws_kms_key.evidence[0].key_id
}

resource "aws_s3_bucket" "evidence" {
  count               = var.evidence_enabled ? 1 : 0
  bucket              = var.evidence_bucket_name
  force_destroy       = false
  object_lock_enabled = true
  tags                = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  count  = var.evidence_enabled ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  count                   = var.evidence_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.evidence[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  count  = var.evidence_enabled ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  count  = var.evidence_enabled ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id

  rule {
    bucket_key_enabled = false

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence[0].arn
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  count  = var.evidence_enabled ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.evidence_bucket_arn, "${local.evidence_bucket_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  count  = var.evidence_enabled ? 1 : 0
  bucket = aws_s3_bucket.evidence[0].id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}
