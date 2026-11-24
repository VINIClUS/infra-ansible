locals {
  audit_actions = ["iam:GetPolicy", "iam:GetPolicyVersion", "s3:GetObject", "s3:ListBucket", "s3:PutObject", "kms:Decrypt", "kms:GenerateDataKey"]
}

resource "aws_iam_role_policy" "delivery_audit" {
  count = var.audit == null ? 0 : 1
  name  = "cnesdata-exact-audit"
  role  = aws_iam_role.delivery["audit"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Deny", Action = ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"], Resource = "*" },
      { Effect = "Deny", NotAction = sort(local.audit_actions), Resource = "*" },
      { Effect = "Deny", Action = ["s3:PutObject"], NotResource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}lifecycle/*" },
      { Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource = local.delivery_session_policy_arns["audit"] },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate", "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"] },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.github_delivery.state_bucket_arn, Condition = { StringEquals = { "s3:prefix" = local.delivery_state_keys } } },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.github_delivery.state_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn" = [var.github_delivery.state_bucket_arn, "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate", "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"] } } },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}lifecycle/*" },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}lifecycle/*",
      Condition = { Null = { "s3:if-none-match" = "false" } } },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.evidence_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}lifecycle/*" } } }
    ]
  })
}
