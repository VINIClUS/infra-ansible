locals {
  delivery_roles = var.github_delivery == null ? {} : {
    plan   = { name = var.github_delivery.plan_role_name, sha = var.github_delivery.plan_workflow_sha }
    deploy = { name = var.github_delivery.deploy_role_name, sha = var.github_delivery.deploy_workflow_sha }
  }
  # These unavoidable global reads have no write side effects. ARN-scoped writes
  # below are an explicit finite API matrix; creation APIs without ARN scope omitted.
  delivery_product_reads = [
    "acm:DescribeCertificate", "acm:ListCertificates", "acm:ListTagsForCertificate",
    "athena:GetWorkGroup", "athena:ListTagsForResource", "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig",
    "cloudfront:GetCachePolicy", "cloudfront:GetOriginAccessControl", "cloudfront:GetResponseHeadersPolicy", "cloudfront:DescribeFunction",
    "cloudfront:ListTagsForResource", "cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory", "cloudwatch:ListTagsForResource",
    "cognito-idp:DescribeUserPool", "cognito-idp:DescribeUserPoolClient", "cognito-idp:DescribeUserPoolDomain", "cognito-idp:DescribeResourceServer",
    "cognito-idp:DescribeManagedLoginBranding", "cognito-idp:ListTagsForResource", "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTimeToLive", "dynamodb:ListTagsOfResource",
    "ec2:DescribeVpcs", "ec2:DescribeVpcAttribute", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:DescribeInternetGateways", "ec2:DescribeRouteTables", "ec2:DescribeVpcEndpoints", "ec2:DescribePrefixLists", "ec2:DescribeNetworkAcls",
    "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:GetLifecyclePolicy", "ecr:ListTagsForResource",
    "ecs:DescribeClusters", "ecs:DescribeTaskDefinition", "ecs:ListTagsForResource", "events:DescribeRule", "events:ListTagsForResource",
    "iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole", "iam:GetPolicy", "iam:GetPolicyVersion",
    "lambda:GetFunction", "lambda:GetFunctionCodeSigningConfig", "lambda:GetPolicy", "lambda:ListVersionsByFunction",
    "logs:DescribeLogGroups", "logs:ListTagsForResource", "logs:DescribeMetricFilters", "scheduler:GetSchedule", "scheduler:GetScheduleGroup", "scheduler:ListTagsForResource",
    "sns:GetTopicAttributes", "sns:GetSubscriptionAttributes", "sns:ListTagsForResource", "states:DescribeStateMachine", "states:ListTagsForResource",
    "wafv2:GetWebACL", "wafv2:ListTagsForResource"
  ]
  delivery_product_writes = [
    "acm:AddTagsToCertificate", "acm:RemoveTagsFromCertificate",
    "athena:UpdateWorkGroup", "athena:TagResource", "athena:UntagResource",
    "cloudfront:UpdateDistribution", "cloudfront:UpdateCachePolicy", "cloudfront:UpdateOriginAccessControl", "cloudfront:UpdateResponseHeadersPolicy", "cloudfront:UpdateFunction", "cloudfront:PublishFunction", "cloudfront:TagResource", "cloudfront:UntagResource",
    "cloudwatch:PutMetricAlarm", "cloudwatch:TagResource", "cloudwatch:UntagResource",
    "cognito-idp:UpdateUserPool", "cognito-idp:UpdateUserPoolClient", "cognito-idp:UpdateResourceServer", "cognito-idp:UpdateManagedLoginBranding", "cognito-idp:TagResource", "cognito-idp:UntagResource",
    "dynamodb:UpdateTable", "dynamodb:UpdateContinuousBackups", "dynamodb:UpdateTimeToLive", "dynamodb:TagResource", "dynamodb:UntagResource",
    "ec2:ModifyVpcAttribute", "ec2:CreateTags", "ec2:DeleteTags", "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress", "ec2:ModifyVpcEndpoint",
    "ecr:PutLifecyclePolicy", "ecr:TagResource", "ecr:UntagResource", "ecs:RegisterTaskDefinition", "ecs:TagResource", "ecs:UntagResource",
    "events:PutRule", "events:TagResource", "events:UntagResource", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:TagRole", "iam:UntagRole",
    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:AddPermission", "lambda:TagResource", "lambda:UntagResource",
    "logs:CreateLogGroup", "logs:PutRetentionPolicy", "logs:PutMetricFilter", "logs:TagResource", "logs:UntagResource",
    "s3:PutBucketPolicy", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration", "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls", "s3:PutLifecycleConfiguration", "s3:PutBucketCORS", "s3:PutBucketObjectLockConfiguration", "s3:PutBucketTagging",
    "scheduler:UpdateSchedule", "scheduler:TagResource", "scheduler:UntagResource", "sns:SetTopicAttributes", "sns:TagResource", "sns:UntagResource",
    "states:UpdateStateMachine", "states:TagResource", "states:UntagResource", "wafv2:UpdateWebACL", "wafv2:TagResource", "wafv2:UntagResource"
  ]
  delivery_global_reads = [
    "acm:ListCertificates", "cloudwatch:DescribeAlarms", "cloudwatch:DescribeAlarmHistory", "logs:DescribeLogGroups",
    "ec2:DescribeVpcs", "ec2:DescribeVpcAttribute", "ec2:DescribeSubnets", "ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:DescribeInternetGateways", "ec2:DescribeRouteTables", "ec2:DescribeVpcEndpoints", "ec2:DescribePrefixLists", "ec2:DescribeNetworkAcls"
  ]
  delivery_bucket_reads = ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls", "s3:GetLifecycleConfiguration", "s3:GetBucketCORS", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketTagging", "s3:GetBucketLogging", "s3:GetBucketWebsite", "s3:GetAccelerateConfiguration"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.github_delivery == null ? 0 : 1
  arn   = var.github_delivery.provider_arn
}

resource "aws_iam_role" "delivery" {
  for_each             = local.delivery_roles
  name                 = each.value.name
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
          "token.actions.githubusercontent.com:sub" = "repo:VINIClUS/CnesData:environment:production:job_workflow_ref:VINIClUS/infra-ansible/.github/workflows/reusable-cnesdata-infra-${each.key}-gate.yml@${each.value.sha}"
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

resource "aws_iam_role_policy" "delivery" {
  for_each = local.delivery_roles
  name     = "cnesdata-exact-delivery"
  role     = aws_iam_role.delivery[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Deny", Action = ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"], Resource = "*" },
      { Effect = "Allow", Action = local.delivery_global_reads, Resource = "*" },
      { Effect = "Allow", Action = ["iam:GetPolicy", "iam:GetPolicyVersion"], Resource = local.delivery_session_policy_arns[each.key] },
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate.tflock" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.github_delivery.state_bucket_arn, Condition = { StringEquals = { "s3:prefix" = ["cnesdata/prod/opentofu.tfstate", "cnesdata/prod/opentofu.tfstate.tflock", "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"] } } },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = var.github_delivery.evidence_bucket_arn, Condition = { StringLike = { "s3:prefix" = "${var.github_delivery.evidence_prefix}*" } } },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.state_kms_arn, Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = ["${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate*", "${var.github_delivery.state_bucket_arn}/shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"] } } },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], Resource = var.github_delivery.evidence_kms_arn, Condition = { StringEquals = { "kms:ViaService" = "s3.us-east-2.amazonaws.com" }, StringLike = { "kms:EncryptionContext:aws:s3:arn" = "${var.github_delivery.evidence_bucket_arn}/${var.github_delivery.evidence_prefix}*" } } }
      ], length(var.github_delivery.read_resource_arns) == 0 ? [] : [
      { Effect = "Allow", Action = concat(tolist(setsubtract(toset(local.delivery_product_reads), toset(local.delivery_global_reads))), local.delivery_bucket_reads), Resource = var.github_delivery.read_resource_arns }
      ], [for statement in concat([
        { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${var.github_delivery.state_bucket_arn}/cnesdata/prod/opentofu.tfstate" }
        ], [for statement in var.github_delivery.product_permissions : { Effect = "Allow", Action = statement.actions, Resource = statement.resources }],
        [for role in var.github_delivery.pass_roles : { Effect = "Allow", Action = ["iam:PassRole"], Resource = role.arn, Condition = { StringEquals = { "iam:PassedToService" = role.service } } }]
    ) : statement if each.key == "deploy"])
  })
}
