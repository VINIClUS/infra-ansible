locals {
  application_predecessor = try(var.application_promotion.predecessor_read, null)
  application_history_names = local.application_predecessor == null ? [] : (
    local.application_predecessor.protocol == "lifecycle" ? ["terminal.json", "lease.json", "checkpoint.json"] : concat(
      ["envelope.json", "lease.json", "checkpoint.json"],
      local.application_predecessor.status == "applied" ? ["drift.json"] : [],
      local.application_predecessor.status == "applied" && local.application_predecessor.purpose == "phase-a" ? ["ecr-before.json"] : []
  ))
  application_history_prefix = local.application_predecessor == null ? null : "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}${local.application_predecessor.protocol == "lifecycle" ? "lifecycle/" : ""}${local.application_predecessor.source_sha}/${local.application_predecessor.run_id}/${local.application_predecessor.run_attempt}/${local.application_predecessor.status}/"
  application_history_arns   = [for name in local.application_history_names : "${local.application_history_prefix}${name}"]
  application_delegations    = var.application_promotion == null ? {} : var.application_promotion.delegations
  application_session_patterns = {
    observer          = ["sp-i-${join("", [for i in range(40) : "?"])}"]
    normal            = ["sp-publish-${join("", [for i in range(40) : "?"])}", "sp-retire-${join("", [for i in range(40) : "?"])}"]
    recovery          = ["sp-rollback-${join("", [for i in range(40) : "?"])}", "sp-readback-${join("", [for i in range(40) : "?"])}", "sp-abort-${join("", [for i in range(40) : "?"])}"]
    seeder            = ["canary-seeder-*"]
    verifier          = ["canary-verifier-*"]
    fence_operator    = ["promotion-fence-*"]
    mode_seed         = [for code in ["us", "rs", "ds"] : "mc-${code}-${join("", [for i in range(40) : "?"])}"]
    mode_dispatch     = [for code in ["ux", "rx", "dx", "dr", "h1", "h2"] : "mc-${code}-${join("", [for i in range(40) : "?"])}"]
    mode_audit_launch = ["mc-ax-${join("", [for i in range(40) : "?"])}"]
    mode_observe      = [for code in ["uo", "ro", "ao", "do"] : "mc-${code}-${join("", [for i in range(40) : "?"])}"]
  }
}

resource "aws_iam_role_policy" "application_history" {
  count = local.application_predecessor == null ? 0 : 1
  name  = "cnesdata-application-predecessor-read"
  role  = aws_iam_role.application[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = local.application_history_arns },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.github_delivery.evidence_kms_arn,
        Condition = { StringEquals = {
          "kms:ViaService"                   = "s3.us-east-2.amazonaws.com"
          "kms:EncryptionContext:aws:s3:arn" = local.application_history_arns
        } }
      }
    ]
  })
}

resource "aws_iam_role" "application" {
  count                = var.application_promotion == null ? 0 : 1
  name                 = var.application_promotion.role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github[0].arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-application-gate.yml@${var.application_promotion.workflow_sha}"
        }
        DateLessThan = { "aws:CurrentTime" = var.application_promotion.enabled_until }
      }
    }]
  })
  lifecycle {
    precondition {
      condition     = var.github_delivery != null
      error_message = "Application reuses the existing reviewed GitHub provider and product coordination locus."
    }
  }
}

resource "aws_iam_role_policy" "application" {
  count = var.application_promotion == null ? 0 : 1
  name  = "cnesdata-application-coordination"
  role  = aws_iam_role.application[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Deny", Action = ["sts:AssumeRole"], NotResource = values(local.application_delegations) },
      { Effect = "Deny", Action = ["sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:TagSession", "sts:SetSourceIdentity"], Resource = "*" },
      { Effect = "Allow", Action = ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"], Resource = concat([aws_iam_role.application[0].arn], values(local.application_delegations)) },
      { Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource = "arn:aws:iam::${var.account_id}:policy/${var.application_promotion.role_name}-session" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}lifecycle/*" },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.state_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json" } } },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.evidence_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}lifecycle/*" } } }
      ], [for role, arn in local.application_delegations : {
        Effect    = "Allow", Action = ["sts:AssumeRole"], Resource = arn,
        Condition = { StringLike = { "sts:RoleSessionName" = local.application_session_patterns[role] } }
    }])
  })
}
