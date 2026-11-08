resource "aws_iam_role" "promotion_fence_operator" {
  count = local.canary_count

  name                 = "${var.name_prefix}-promotion-fence-operator"
  assume_role_policy   = local.canary_principal_trust["operator"]
  max_session_duration = local.canary_max_session_duration
  tags                 = local.canary_tags
}

resource "aws_iam_role_policy" "promotion_fence_operator" {
  count = local.canary_count

  name = "${var.name_prefix}-promotion-fence-operator-gate"
  role = aws_iam_role.promotion_fence_operator[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:GetItem"
        Resource = var.runtime_grants.table_arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = ["ENV#prod#FENCE", "ENV#prod#SEMAPHORE"]
          }
          Null = { "dynamodb:LeadingKeys" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = "dynamodb:UpdateItem"
        Resource = var.runtime_grants.table_arn
        Condition = {
          "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["ENV#prod#FENCE"] }
          Null                        = { "dynamodb:LeadingKeys" = "false" }
        }
      },
    ]
  })
}
