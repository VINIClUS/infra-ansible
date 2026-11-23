locals {
  phase_inputs_writer_role_name = "cnesdata-prod-phase-inputs-writer"
}

resource "aws_iam_role" "phase_inputs_writer" {
  count                = var.phase_inputs_writer_enabled ? 1 : 0
  name                 = local.phase_inputs_writer_role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github[0].arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud"              = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub"              = "repo:VINIClUS/CnesData:environment:production"
          "token.actions.githubusercontent.com:job_workflow_ref" = "VINIClUS/CnesData/.github/workflows/phase-a-prepare.yml@refs/heads/main"
        }
      }
    }]
  })
  lifecycle {
    precondition {
      condition     = data.aws_iam_openid_connect_provider.github[0].url == "token.actions.githubusercontent.com" && sort(tolist(data.aws_iam_openid_connect_provider.github[0].client_id_list)) == sort(var.github_delivery.provider_client_ids) && sort(tolist(data.aws_iam_openid_connect_provider.github[0].thumbprint_list)) == sort(var.github_delivery.provider_thumbprints)
      error_message = "Shared GitHub provider URL/audience readback differs; never create another provider."
    }
  }
}

resource "aws_iam_role_policy" "phase_inputs_writer" {
  count = var.phase_inputs_writer_enabled ? 1 : 0
  name  = "cnesdata-exact-phase-inputs-writer"
  role  = aws_iam_role.phase_inputs_writer[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}phase-inputs/*",
      Condition = { Null = { "s3:if-none-match" = "false" } } },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Encrypt"], Resource = var.github_delivery.evidence_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}phase-inputs/*" } } }
    ]
  })
}
