resource "aws_iam_role" "ext2_gate" {
  count                = var.ext2_enabled ? 1 : 0
  name                 = "cnesdata-delivery-ext2-gate"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.github_delivery.provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-signing-gate.yml@${var.ext2.workflow_sha}"
        }
      }
    }]
  })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.ext2 != null && var.github_delivery != null
      error_message = "EXT2 needs the owner-frozen contract and existing shared GitHub provider."
    }
  }
}

resource "aws_kms_key" "ext2_signing" {
  count                    = var.ext2_enabled ? 1 : 0
  description              = "CnesData EXT2 activation signing; not an encryption key."
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  is_enabled               = true
  multi_region             = false
  deletion_window_in_days  = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OwnerAdministration"
        Effect    = "Allow"
        Principal = { AWS = var.ext2.admin_arns }
        Action = [
          "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:GetPublicKey",
          "kms:EnableKey", "kms:DisableKey", "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion", "kms:TagResource", "kms:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid       = "GateRead"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.ext2_gate[0].arn }
        Action    = ["kms:DescribeKey", "kms:GetPublicKey", "kms:GetKeyPolicy"]
        Resource  = "*"
      },
      {
        Sid       = "GateSign"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.ext2_gate[0].arn }
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:SigningAlgorithm" = "ECDSA_SHA_256", "kms:MessageType" = "DIGEST" }
          DateLessThan = { "aws:CurrentTime" = var.ext2.enabled_until }
        }
      }
    ]
  })
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "ext2_signing" {
  count         = var.ext2_enabled ? 1 : 0
  name          = "alias/cnesdata-delivery-ext2-signing"
  target_key_id = aws_kms_key.ext2_signing[0].key_id
  lifecycle {
    prevent_destroy = true
  }
}
