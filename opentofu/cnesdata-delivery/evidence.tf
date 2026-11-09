# This root owns no evidence bucket, bucket configuration, bucket policy or cipher key.
resource "aws_iam_role_policy" "ext2_gate" {
  count = var.ext2_enabled ? 1 : 0
  name  = "cnesdata-delivery-ext2-gate"
  role  = aws_iam_role.ext2_gate[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Deny"
        Action   = ["s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
        Resource = concat(var.ext2.current_object_arns, var.ext2.history_object_arns)
      },
      { Effect = "Deny", Action = "s3:ListBucketMultipartUploads", Resource = var.ext2.bucket_arn },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersion", "s3:GetObjectRetention"]
        Resource = concat(var.ext2.current_object_arns, var.ext2.history_object_arns)
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetEncryptionConfiguration", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration"]
        Resource = var.ext2.bucket_arn
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = var.ext2.current_object_arns
        Condition = {
          StringEquals = {
            "s3:object-lock-mode"                            = "COMPLIANCE"
            "s3:x-amz-server-side-encryption"                = "aws:kms"
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = var.ext2.cipher_kms_key_arn
          }
          DateEquals   = { "s3:object-lock-retain-until-date" = var.ext2.retain_until }
          DateLessThan = { "aws:CurrentTime" = var.ext2.enabled_until }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObjectRetention"
        Resource = var.ext2.current_object_arns
        Condition = {
          StringEquals = { "s3:object-lock-mode" = "COMPLIANCE" }
          DateEquals   = { "s3:object-lock-retain-until-date" = var.ext2.retain_until }
          DateLessThan = { "aws:CurrentTime" = var.ext2.enabled_until }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"]
        Resource = aws_kms_key.ext2_signing[0].arn
      },
      {
        Effect   = "Allow"
        Action   = "kms:Sign"
        Resource = aws_kms_key.ext2_signing[0].arn
        Condition = {
          StringEquals = { "kms:SigningAlgorithm" = "ECDSA_SHA_256", "kms:MessageType" = "DIGEST" }
          DateLessThan = { "aws:CurrentTime" = var.ext2.enabled_until }
        }
      },
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.ext2.cipher_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = "s3.us-east-2.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = concat(var.ext2.current_object_arns, var.ext2.history_object_arns)
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "kms:GenerateDataKey"
        Resource = var.ext2.cipher_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = "s3.us-east-2.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = var.ext2.current_object_arns
          }
          DateLessThan = { "aws:CurrentTime" = var.ext2.enabled_until }
        }
      }
    ]
  })
  lifecycle {
    prevent_destroy = true
  }
}
