output "github_oidc_provider" {
  description = "Inputs for github_delivery.provider_*; thumbprint_list is the AWS readback. Null while disabled."
  value = !var.github_oidc_enabled ? null : {
    arn             = aws_iam_openid_connect_provider.github[0].arn
    url             = aws_iam_openid_connect_provider.github[0].url
    client_id_list  = aws_iam_openid_connect_provider.github[0].client_id_list
    thumbprint_list = aws_iam_openid_connect_provider.github[0].thumbprint_list
  }
}

output "evidence_storage" {
  description = "Fragment for shared_outputs kms_key_arn and storage.evidence_bucket_*; not a complete shared_outputs. Null while disabled."
  value = !var.evidence_enabled ? null : {
    evidence_bucket_name = var.evidence_bucket_name
    evidence_bucket_arn  = local.evidence_bucket_arn
    kms_key_arn          = aws_kms_key.evidence[0].arn
  }
}
