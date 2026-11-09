locals {
  host_gate_enabled = var.host_gate != null
}

resource "aws_iam_role" "host_gate" {
  count                = local.host_gate_enabled ? 1 : 0
  name                 = "cnesdata-delivery-host"
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
          "token.actions.githubusercontent.com:sub" = "repo:VINIClUS/CnesData:ref:refs/heads/develop:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-host-deploy-gate.yml@${var.host_gate.workflow_sha}"
        }
      }
    }]
  })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.github_delivery != null
      error_message = "Host gate reuses the governed GitHub OIDC provider; it creates no provider."
    }
  }
}

resource "aws_iam_role_policy" "host_gate" {
  count = local.host_gate_enabled ? 1 : 0
  name  = "exact-host-inputs"
  role  = aws_iam_role.host_gate[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [for object in var.host_gate.objects : {
        Effect    = "Allow"
        Action    = ["s3:GetObjectVersion"]
        Resource  = object.arn
        Condition = { StringEquals = { "s3:VersionId" = object.version } }
      }],
      [{
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = var.host_gate.ssm_parameter_arns
      }],
      [for key in var.host_gate.decrypt_keys : {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = key.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = "s3.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = key.object_arns
          }
        }
      }],
      [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.host_gate.ssm_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                      = "ssm.${var.region}.amazonaws.com"
            "kms:EncryptionContext:PARAMETER_ARN" = var.host_gate.ssm_parameter_arns
          }
        }
        }, {
        Sid      = "NoCrossAssumeOrMutation"
        Effect   = "Deny"
        Action   = ["sts:AssumeRole", "iam:PassRole", "ecs:RunTask", "s3:Put*", "s3:Delete*", "s3:List*", "ssm:Put*", "ssm:Delete*", "kms:Encrypt", "kms:GenerateDataKey*", "kms:Sign"]
        Resource = "*"
      }]
    )
  })
}
