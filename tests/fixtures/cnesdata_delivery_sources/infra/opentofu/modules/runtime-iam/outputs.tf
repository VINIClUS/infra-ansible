locals {
  static_roles = {
    observer = one(aws_iam_role.static_observer[*])
    normal   = one(aws_iam_role.static_normal[*])
    recovery = one(aws_iam_role.static_recovery[*])
  }
  static_inline_policies = {
    observer = one(aws_iam_role_policy.static_observer[*])
    normal   = one(aws_iam_role_policy.static_normal[*])
    recovery = one(aws_iam_role_policy.static_recovery[*])
  }
  static_aliases = local.static_enabled ? (
    local.static_operational ? ["observer", "normal", "recovery"] : ["observer"]
  ) : []
}

output "static_promotion_iam_contract" {
  description = "Private static references and exact policy/trust commitments, without credentials."
  sensitive   = true
  value = !local.static_enabled ? null : {
    mode                    = var.static_promotion.mode
    binding_sha256          = sha256("${jsonencode(local.static_binding)}\n")
    static_plan_sha256      = local.static_binding.static_plan_sha256
    inventory_sha256        = var.static_promotion.inventory_sha256
    bucket_arn              = local.static_bucket
    distribution_arn        = local.static_distribution
    freeze_target_role_arns = local.static_operational ? [local.static_roles.normal.arn] : []
    freeze_excluded_role_arns = sort([
      for alias in local.static_aliases : local.static_roles[alias].arn if alias != "normal"
    ])
    delegations = { for alias in local.static_aliases : alias => {
      role_arn       = local.static_roles[alias].arn
      role_name      = local.static_roles[alias].name
      role_address   = "module.runtime_iam.aws_iam_role.static_${alias}[0]"
      policy_address = "module.runtime_iam.aws_iam_role_policy.static_${alias}[0]"
      policy_name    = local.static_inline_policies[alias].name
      session_names  = local.static_sessions[alias]
      trust_sha256   = sha256(local.static_roles[alias].assume_role_policy)
      policy_sha256  = sha256(local.static_inline_policies[alias].policy)
    } }
  }
}

locals {
  mode_roles = {
    mode_seed = one([for role in aws_iam_role.mode_seed : {
      arn = role.arn, name = role.name, assume_role_policy = role.assume_role_policy
    }])
    mode_dispatch = one([for role in aws_iam_role.mode_dispatch : {
      arn = role.arn, name = role.name, assume_role_policy = role.assume_role_policy
    }])
    mode_audit_launch = one([for role in aws_iam_role.mode_audit_launch : {
      arn = role.arn, name = role.name, assume_role_policy = role.assume_role_policy
    }])
    mode_observe = one([for role in aws_iam_role.mode_observe : {
      arn = role.arn, name = role.name, assume_role_policy = role.assume_role_policy
    }])
  }
  mode_inline_policies = {
    mode_seed         = one(aws_iam_role_policy.mode_seed[*])
    mode_dispatch     = one(aws_iam_role_policy.mode_dispatch[*])
    mode_audit_launch = one(aws_iam_role_policy.mode_audit_launch[*])
    mode_observe      = one(aws_iam_role_policy.mode_observe[*])
  }
}

output "mode_canary_capabilities" {
  description = "Private exact commitments, with no policy bodies or credentials."
  sensitive   = true
  value = !local.mode_enabled ? null : {
    schema_version          = 2
    context_kind            = var.mode_canary.context_kind
    owner_sha256            = var.mode_canary.owner.owner_sha256
    generation              = var.mode_canary.owner.generation
    context_manifest_sha256 = var.mode_canary.context_manifest.sha256
    activation_sha256       = local.mode_manifest.activation_sha256
    resources_sha256        = local.mode_manifest.resources_sha256
    enabled_until           = var.mode_canary.enabled_until
    delegations = { for alias in local.mode_aliases : alias => {
      role_arn       = local.mode_roles[alias].arn
      role_name      = local.mode_roles[alias].name
      role_address   = "module.runtime_iam.aws_iam_role.${alias}[0]"
      policy_address = "module.runtime_iam.aws_iam_role_policy.${alias}[0]"
      policy_name    = local.mode_inline_policies[alias].name
      session_names  = local.mode_sessions[alias]
      trust_sha256   = sha256(local.mode_roles[alias].assume_role_policy)
      policy_sha256  = sha256(local.mode_inline_policies[alias].policy)
    } }
  }
}

output "demo_seed_iam_contract" {
  description = "Dedicated demo consumer contract, or null when demo_seed is disabled."
  value = var.demo_seed == null ? null : {
    contract_version             = "cnesdata.demo-seed-iam/v1"
    role_arn                     = aws_iam_role.demo_seed[0].arn
    policy_name                  = aws_iam_role_policy.demo_seed[0].name
    policy_sha256                = sha256(aws_iam_role_policy.demo_seed[0].policy)
    table_arn                    = var.runtime_grants.table_arn
    tenant_partition_key         = var.demo_seed.tenant_partition_key
    role_session_name            = "demo-seed"
    max_session_duration_seconds = aws_iam_role.demo_seed[0].max_session_duration
    allowed_actions              = local.demo_seed_actions
  }
}

output "execution_role_arn" {
  description = "Shared execution identity ARN for processor tasks."
  value       = aws_iam_role.execution.arn
}

output "execution_role_name" {
  description = "Shared execution identity name for processor tasks."
  value       = aws_iam_role.execution.name
}

output "task_role_arns" {
  description = "Initially policy-free task identity ARNs by processor mode."
  value       = { for mode, role in aws_iam_role.task : mode => role.arn }
}

output "task_role_names" {
  description = "Initially policy-free task identity names by processor mode."
  value       = { for mode, role in aws_iam_role.task : mode => role.name }
}

output "step_functions_role_id" {
  description = "Step Functions role ID, or null for the base module."
  value       = one(aws_iam_role.step_functions[*].id)
}

output "step_functions_role_arn" {
  description = "Step Functions role ARN, or null for the base module."
  value       = one(aws_iam_role.step_functions[*].arn)
}

output "canary_task_role_arn" {
  description = "Canary task role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_task[*].arn)
}

output "canary_execution_role_arn" {
  description = "Canary execution role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_execution[*].arn)
}

output "canary_seeder_role_arn" {
  description = "Canary seeder role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_seeder[*].arn)
}

output "canary_verifier_role_arn" {
  description = "Canary verifier role ARN, or null without a release activation."
  value       = one(aws_iam_role.canary_verifier[*].arn)
}

output "canary_verifier_role_id" {
  description = "Canary verifier role name for the processing RunTask grant, or null."
  value       = one(aws_iam_role.canary_verifier[*].name)
}

output "promotion_fence_operator_role_arn" {
  description = "Promotion fence operator role ARN, or null without a release activation."
  value       = one(aws_iam_role.promotion_fence_operator[*].arn)
}

output "canary_session_names" {
  description = "Release-bound role session names required by the canary trust policies."
  value       = local.canary_session_names
}

output "canary_event_id" {
  description = "Release-bound canary event ID, or null without a release activation."
  value       = local.canary_event_id
}

output "canary_object_arns" {
  description = "Release-bound canary audit object ARNs read by the verifier."
  value       = local.canary_object_arns
}

output "canary_max_session_duration" {
  description = "Maximum session seconds of every canary and promotion role."
  value       = local.canary_max_session_duration
}
