# Single managed GitHub provider; cnesdata-delivery reads it by ARN and never creates one.
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.github_oidc_enabled ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags

  lifecycle {
    prevent_destroy = true
  }
}
