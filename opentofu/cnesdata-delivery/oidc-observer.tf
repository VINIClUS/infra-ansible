locals {
  observer_role_name = "cnesdata-delivery-observer"
  observer_reads = [
    "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetRolePolicy",
    "ecs:DescribeTaskDefinition", "ecs:DescribeClusters",
    "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
    "s3:GetObject", "s3:ListBucket", "kms:Decrypt",
    "dynamodb:DescribeTable", "s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration"
  ]
  observer_session_policy_arns = var.github_delivery == null ? [] : concat(
    values(local.delivery_session_policy_arns),
    var.application_promotion == null ? [] : [
      "arn:aws:iam::${var.account_id}:policy/${var.application_promotion.role_name}-session",
      "arn:aws:iam::${var.account_id}:policy/${var.application_promotion.role_name}-ops-session"
    ],
    local.delivery_activation_policy_arn == null ? [] : [local.delivery_activation_policy_arn]
  )
}

resource "aws_iam_role" "observer" {
  count                = var.observer == null ? 0 : 1
  name                 = local.observer_role_name
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
          "token.actions.githubusercontent.com:sub"              = "repo:VINIClUS/infra-ansible:environment:cnesdata-observer"
          "token.actions.githubusercontent.com:job_workflow_ref" = "VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-observer.yml@${var.observer.workflow_sha}"
        }
        DateLessThan = { "aws:CurrentTime" = var.github_delivery.enabled_until }
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

resource "aws_iam_role_policy" "observer" {
  count = var.observer == null ? 0 : 1
  name  = "cnesdata-exact-observer"
  role  = aws_iam_role.observer[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Deny", Action = ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"], Resource = "*" },
      { Effect = "Deny", NotAction = sort(local.observer_reads), Resource = "*" },
      { Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource = local.observer_session_policy_arns },
      { Effect = "Allow", Action = ["iam:GetRole", "iam:GetRolePolicy"], Resource = "arn:aws:iam::${var.account_id}:role/cnesdata-prod-*" },
      { Effect = "Allow", Action = ["ecs:DescribeTaskDefinition"], Resource = "*" },
      { Effect = "Allow", Action = ["ecs:DescribeClusters"], Resource = var.observer.cluster_arn },
      { Effect = "Allow", Action = ["ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource = var.observer.repository_arn },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.github_delivery.state_bucket_arn, Condition = { StringEquals = { "s3:prefix" = "env:/" } } },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.github_delivery.state_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn" = ["${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate", var.github_delivery.state_bucket_arn] } } },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}phase-inputs/*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.github_delivery.evidence_bucket_arn, Condition = { StringLike = { "s3:prefix" = "${var.github_delivery.evidence_prefix}phase-inputs/*" } } },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.github_delivery.evidence_kms_arn,
      Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}phase-inputs/*" } } },
      { Effect = "Allow", Action = ["dynamodb:DescribeTable"], Resource = var.observer.table_arns },
      { Effect = "Allow", Action = ["s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration"], Resource = var.observer.bucket_arns }
    ]
  })
}
