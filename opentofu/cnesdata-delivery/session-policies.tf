locals {
  delivery_state_keys = [
    "cnesdata/prod/opentofu.tfstate",
    "cnesdata/prod/opentofu.tfstate.tflock",
    "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
  ]
  delivery_session_policy_arns = {
    for role, settings in local.delivery_roles : role => "arn:aws:iam::${var.account_id}:policy/${settings.name}-session"
  }
}

resource "aws_iam_policy" "delivery_session" {
  for_each    = local.delivery_roles
  name        = "${each.value.name}-session"
  description = "Session restriction only; never attach as identity or permissions boundary."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", NotAction = ["s3:*Object*", "s3:ListBucket*", "s3:*Multipart*", "kms:*"], Resource = "*" },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate.tflock" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.github_delivery.state_bucket_arn, Condition = { StringEquals = { "s3:prefix" = local.delivery_state_keys } } },
      { Effect = "Allow", Action = ["s3:ListBucket"], NotResource = var.github_delivery.evidence_bucket_arn },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.state_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn" = [for key in local.delivery_state_keys : "${var.github_delivery.state_bucket_arn}/${key}"] } } },
      { Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource = local.delivery_session_policy_arns[each.key] },
      { Effect = "Deny", Action = ["s3:DeleteObject"], NotResource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate.tflock" },
      { Effect = "Deny", Action = ["s3:*ObjectVersion*", "s3:*ObjectAcl", "s3:*ObjectTagging", "s3:*ObjectRetention", "s3:*ObjectLegalHold", "s3:RestoreObject", "s3:GetObjectAttributes", "s3:*Multipart*"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}*" },
      { Effect = "Deny", Action = ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"], Resource = var.github_delivery.evidence_bucket_arn },
      { Effect = "Deny", Action = ["kms:*"], Resource = distinct([var.github_delivery.state_kms_arn, var.github_delivery.evidence_kms_arn]), Condition = { StringNotEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" } } },
      { Effect = "Deny", Action = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion", "iam:DeletePolicy", "iam:Attach*Policy", "iam:Put*PermissionsBoundary"], Resource = "*" }
      ], each.key == "deploy" ? [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate" }
      ] : [], length(var.github_delivery.read_resource_arns) == 0 ? [] : [
      { Effect = "Allow", Action = ["s3:GetBucketObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration"], Resource = var.github_delivery.read_resource_arns }
    ])
  })
  lifecycle {
    precondition {
      condition     = !contains(var.github_delivery.read_resource_arns, var.github_delivery.evidence_bucket_arn)
      error_message = "Shared evidence/product listing needs independently governed exact product prefixes; no namespace widening."
    }
  }
}
