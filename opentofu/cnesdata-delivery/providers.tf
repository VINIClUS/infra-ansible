provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
}

data "aws_caller_identity" "current" {}
