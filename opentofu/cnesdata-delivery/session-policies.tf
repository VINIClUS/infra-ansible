locals {
  delivery_state_keys = [
    "cnesdata/prod/opentofu.tfstate",
    "cnesdata/prod/opentofu.tfstate.tflock",
    "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
  ]
  delivery_evidence_prefix_denies = ["s3:*ObjectVersion*", "s3:*ObjectAcl", "s3:*ObjectTagging", "s3:*ObjectRetention", "s3:*ObjectLegalHold", "s3:RestoreObject", "s3:GetObjectAttributes", "s3:*Multipart*"]
  delivery_activation_denies = concat(
    local.delivery_activation == null ? [] : [{ Effect = "Deny", Action = ["s3:*ObjectVersion*", "s3:*ObjectRetention"], NotResource = local.delivery_activation_objects }],
    local.delivery_activation == null ? [] : [{ Effect = "Deny", NotAction = ["s3:GetObjectVersion", "s3:GetObjectRetention"], Resource = local.delivery_activation_objects }],
    local.delivery_activation == null ? [] : [{ Effect = "Deny", Action = ["kms:*"], Resource = local.delivery_activation.cipher_kms_key_arn, Condition = { StringNotEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" } } }]
  )
  delivery_session_policy_arns = {
    for role, settings in local.delivery_roles : role => "arn:aws:iam::${var.account_id}:policy/${settings.name}-session"
  }
}

resource "aws_iam_policy" "application_session" {
  count       = var.application_promotion == null ? 0 : 1
  name        = "${var.application_promotion.role_name}-session"
  description = "Application session restriction only; never attach as identity or permissions boundary."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Action = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion", "sts:AssumeRole"], Resource = "*" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json" },
      { Effect    = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.state_kms_arn,
        Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json" } }
      },
      { Effect = "Deny", Action = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion", "iam:DeletePolicy", "iam:Attach*Policy", "iam:Put*PermissionsBoundary"], Resource = "*" }
    ], flatten([for history in aws_iam_role_policy.application_history : jsondecode(history.policy).Statement]))
  })
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
      { Effect = "Deny", Action = each.key == "plan" && local.delivery_activation != null ? [for action in local.delivery_evidence_prefix_denies : action if !contains(["s3:*ObjectVersion*", "s3:*ObjectRetention"], action)] : local.delivery_evidence_prefix_denies, Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}*" },
      { Effect = "Deny", Action = ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"], Resource = var.github_delivery.evidence_bucket_arn },
      { Effect = "Deny", Action = ["kms:*"], Resource = distinct([var.github_delivery.state_kms_arn, var.github_delivery.evidence_kms_arn]), Condition = { StringNotEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" } } },
      { Effect = "Deny", Action = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion", "iam:DeletePolicy", "iam:Attach*Policy", "iam:Put*PermissionsBoundary"], Resource = "*" }
      ], each.key == "deploy" ? [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate" }
      ] : [], length(var.github_delivery.read_resource_arns) == 0 ? [] : [
      { Effect = "Allow", Action = ["s3:GetBucketObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration"], Resource = var.github_delivery.read_resource_arns }
    ], [for statement in concat(local.delivery_activation_allows, local.delivery_activation_denies) : statement if each.key == "plan"])
  })
  lifecycle {
    precondition {
      condition     = !contains(var.github_delivery.read_resource_arns, var.github_delivery.evidence_bucket_arn)
      error_message = "Shared evidence/product listing needs independently governed exact product prefixes; no namespace widening."
    }
  }
}
