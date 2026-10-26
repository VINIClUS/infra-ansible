locals {
  backend_roots = [var.roots.foundation, var.roots["budget-backend"]]
  backend_buckets = [
    for root in local.backend_roots : "arn:aws:s3:::${root.backend.bucket}"
  ]
  backend_logs = [
    for root in local.backend_roots : "arn:aws:s3:::${root.logging.bucket}"
  ]
  backend_objects = [
    for root in local.backend_roots :
    "arn:aws:s3:::${root.backend.bucket}/${root.backend.key}"
  ]
  backend_locks = [
    for root in local.backend_roots :
    "arn:aws:s3:::${root.backend.bucket}/${root.backend.key}.tflock"
  ]
  executor_statements = [
    {
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
      Resource = concat(local.backend_objects, local.backend_locks)
    },
    {
      Effect   = "Allow"
      Action   = "s3:DeleteObject"
      Resource = local.backend_locks
    },
    {
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
      Resource = local.backend_buckets
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      Resource = aws_kms_key.foundation.arn
    },
  ]
  readback_statements = [
    {
      Effect = "Allow"
      Action = [
        "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketLogging",
        "s3:GetEncryptionConfiguration", "s3:GetBucketPolicy",
        "s3:GetBucketOwnershipControls", "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
      ]
      Resource = concat(local.backend_buckets, local.backend_logs)
    },
    {
      Effect   = "Allow"
      Action   = "s3:ListBucket"
      Resource = local.backend_buckets
    },
    {
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectVersion"]
      Resource = concat(local.backend_objects, local.backend_locks)
    },
    {
      Effect   = "Allow"
      Action   = "kms:Decrypt"
      Resource = aws_kms_key.foundation.arn
    },
    {
      Effect = "Allow"
      Action = [
        "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
      ]
      Resource = aws_kms_key.foundation.arn
    },
  ]
}

resource "aws_iam_policy" "executor_boundary" {
  name = var.identities.boundary.name
  path = var.identities.boundary.path
  policy = replace(
    jsonencode({ Version = "2012-10-17", Statement = local.executor_statements }),
    aws_kms_key.foundation.arn,
    aws_kms_key.foundation.arn,
  )
  tags = local.tags
}

resource "aws_kms_key" "foundation" {
  description                        = "CnesData bootstrap foundation key"
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  is_enabled                         = true
  enable_key_rotation                = true
  multi_region                       = false
  deletion_window_in_days            = 30
  bypass_policy_lockout_safety_check = false
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
  tags = local.tags

  lifecycle {
    prevent_destroy = true
  }
}
