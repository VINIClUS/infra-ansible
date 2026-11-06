resource "aws_iam_user" "bootstrap_operator" {
  name          = var.identities.operator.name
  path          = var.identities.operator.path
  force_destroy = false
  tags          = local.tags
}

resource "aws_iam_user_policy_attachment" "local_login" {
  user       = aws_iam_user.bootstrap_operator.name
  policy_arn = "arn:aws:iam::aws:policy/SignInLocalDevelopmentAccess"
}

resource "aws_iam_user_policy" "local_assume" {
  name = "cnesdata-bootstrap-local-assume"
  user = aws_iam_user.bootstrap_operator.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = [aws_iam_role.bootstrap_readback.arn, aws_iam_role.bootstrap_executor.arn]
      Condition = {
        Bool = { "aws:MultiFactorAuthPresent" = "true" }
      }
    }]
  })
}

resource "aws_iam_role" "bootstrap_readback" {
  name                 = var.identities.readback.name
  path                 = var.identities.readback.path
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.bootstrap_operator.arn }
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role" "bootstrap_executor" {
  name                 = var.identities.executor.name
  path                 = var.identities.executor.path
  max_session_duration = 3600
  permissions_boundary = aws_iam_policy.executor_boundary.arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = aws_iam_user.bootstrap_operator.arn }
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "bootstrap_readback" {
  name = "cnesdata-bootstrap-readback"
  role = aws_iam_role.bootstrap_readback.name
  policy = replace(
    jsonencode({
      Version   = "2012-10-17"
      Statement = local.readback_statements
    }),
    aws_kms_key.foundation.arn,
    aws_kms_key.foundation.arn,
  )
}

resource "aws_iam_role_policy" "bootstrap_executor" {
  name = "cnesdata-bootstrap-executor"
  role = aws_iam_role.bootstrap_executor.name
  policy = replace(
    jsonencode({
      Version   = "2012-10-17"
      Statement = local.executor_statements
    }),
    aws_kms_key.foundation.arn,
    aws_kms_key.foundation.arn,
  )
}
