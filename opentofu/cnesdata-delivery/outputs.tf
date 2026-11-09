output "roles_anywhere" {
  description = "Exact roles_anywhere v2 fragment only; null during closed initialization. Not complete shared_outputs."
  value = !var.activation_enabled ? null : {
    api_role_arn     = aws_iam_role.api.arn
    profile_arn      = aws_rolesanywhere_profile.api.arn
    trust_anchor_arn = aws_rolesanywhere_trust_anchor.ca.arn
    crl = {
      crl_id      = try(var.crl_handoff.crl_id, null)
      enabled     = try(var.crl_handoff.enabled, false)
      next_update = try(var.crl_handoff.next_update, null)
      sha256      = try(var.crl_handoff.sha256, null)
    }
  }
}

output "initialization" {
  description = "Identifiers for the controlled CRL import/readback only; never a consumer-ready shared_outputs object."
  value = {
    account_id       = var.account_id
    region           = var.region
    api_role_arn     = aws_iam_role.api.arn
    profile_arn      = aws_rolesanywhere_profile.api.arn
    trust_anchor_arn = aws_rolesanywhere_trust_anchor.ca.arn
  }
}

output "crl_handoff_sha256" {
  description = "Reviewed input digest, not proof of live AWS state."
  value       = var.activation_enabled ? var.crl_handoff_sha256 : null
}

output "github" {
  description = "Only the two EXT1 v2 leaves; null if closed. Host role and full shared_outputs belong to their owners."
  value = var.github_delivery == null ? null : {
    infrastructure_plan_role_arn   = aws_iam_role.delivery["plan"].arn
    infrastructure_deploy_role_arn = aws_iam_role.delivery["deploy"].arn
  }
}

output "ext2" {
  description = "Private delivery-only audit identifiers; never shared_outputs/v2 or an activation receipt."
  sensitive   = true
  value = var.ext2_enabled ? {
    role_arn        = aws_iam_role.ext2_gate[0].arn
    signing_key_arn = aws_kms_key.ext2_signing[0].arn
    signing_alias   = aws_kms_alias.ext2_signing[0].name
  } : null
}
