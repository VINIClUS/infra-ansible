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

output "application_promotion" {
  description = "Private application_promotion fragment4: exact purpose callers, ten aliases and governed predecessor reads; never a shared_outputs/v2 leaf or activation receipt."
  sensitive   = true
  value = var.application_promotion == null ? null : merge({
    fragment_version      = 4
    account_id            = var.account_id
    region                = var.region
    application_role_arn  = aws_iam_role.application[0].arn
    application_role_name = aws_iam_role.application[0].name
    producer = {
      repository            = "VINIClUS/infra-ansible"
      workflow_path         = ".github/workflows/reusable-cnesdata-application-gate.yml"
      workflow_sha          = var.application_promotion.workflow_sha
      source_closure_sha256 = var.application_promotion.source_closure_sha256
    }
    caller_by_purpose = {
      for purpose, workflow in { promotion = "promote-production.yml", mode-readiness-drill = "readiness-production.yml" } : purpose => {
        repository                         = "VINIClUS/CnesData"
        workflow_path                      = ".github/workflows/${workflow}"
        ref                                = "refs/heads/develop"
        environment                        = "production"
      }
    }
    provider_arn = var.github_delivery.provider_arn
    lease = {
      bucket_arn  = var.github_delivery.state_bucket_arn
      key         = "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json"
      kms_key_arn = var.github_delivery.state_kms_arn
    }
    evidence = {
      bucket_arn  = var.github_delivery.evidence_bucket_arn
      prefix      = "${var.github_delivery.evidence_prefix}lifecycle/"
      kms_key_arn = var.github_delivery.evidence_kms_arn
    }
    delegations   = local.application_delegations
    trust_sha256  = sha256(aws_iam_role.application[0].assume_role_policy)
    policy_sha256 = sha256(aws_iam_role_policy.application[0].policy)
    enabled_until = var.application_promotion.enabled_until
    }, { for key, value in {
      predecessor_reads = local.application_predecessor == null ? null : merge(local.application_predecessor, {
        object_arns   = local.application_history_arns
        policy_sha256 = sha256(aws_iam_role_policy.application_history[0].policy)
      })
  } : key => value if value != null })
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
  description = "Owned EXT1/EXT3 github leaves only; null if closed. This fragment is not complete shared_outputs/v2."
  value = var.github_delivery == null ? null : merge({
    infrastructure_plan_role_arn   = aws_iam_role.delivery["plan"].arn
    infrastructure_deploy_role_arn = aws_iam_role.delivery["deploy"].arn
  }, var.host_gate == null ? {} : { host_deploy_role_arn = aws_iam_role.host_gate[0].arn })
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
