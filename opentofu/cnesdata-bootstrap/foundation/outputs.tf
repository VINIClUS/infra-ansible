output "bootstrap_foundation" {
  value = {
    contract_version     = 1
    account_id           = var.account_id
    region               = var.region
    kms_key_arn          = aws_kms_key.foundation.arn
    ready_for_product    = false
    ready_for_budget_sns = false
    backends = {
      foundation = {
        bucket       = aws_s3_bucket.state.bucket
        key          = var.roots.foundation.backend.key
        region       = var.region
        use_lockfile = true
        encrypt      = true
        kms_key_id   = aws_kms_key.foundation.arn
        owner        = var.roots.foundation.owner
      }
    }
  }
}
