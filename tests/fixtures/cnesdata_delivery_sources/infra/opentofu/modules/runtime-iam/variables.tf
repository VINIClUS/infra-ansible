variable "tags" {
  description = "Ownership metadata for the dedicated static identities only."
  type        = map(string)
  default     = {}
}

variable "static_web" {
  description = "Internal bucket/distribution references resolved by the product root."
  type        = any
  default     = null
}

variable "demo_seed" {
  description = "Exact demo tenant seed grant, or null to create no demo identity."
  type = object({
    tenant_partition_key  = string
    trusted_principal_arn = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.demo_seed == null ? true : can(regex(
      "^TENANT#([0-9a-f]{2})+$", var.demo_seed.tenant_partition_key,
    ))
    error_message = "demo_seed_partition=expected_exact_lowercase_even_hex_tenant"
  }

  validation {
    condition     = var.demo_seed == null ? true : var.runtime_grants != null
    error_message = "demo_seed_runtime_grants=required"
  }

  validation {
    condition = var.demo_seed == null ? true : try(
      can(regex(
        "^arn:aws:iam::[0-9]{12}:role/([^/*?]+/)*[A-Za-z0-9_+=,.@-]{1,64}$",
        var.demo_seed.trusted_principal_arn,
      )) &&
      can(regex("^[!-~]+$", var.demo_seed.trusted_principal_arn)) &&
      split(":", var.demo_seed.trusted_principal_arn)[4] == var.account_id,
      false,
    )
    error_message = "demo_seed_principal=expected_exact_same_account_ascii_iam_role"
  }

  validation {
    condition     = var.demo_seed == null ? true : length("${var.name_prefix}-demo-seed") <= 64
    error_message = "demo_seed_role_name=expected_max64_chars"
  }
}

variable "mode_canary" {
  description = "Closed owner-bound mode capability contract, or null to create no capability."
  type        = any
  default     = null
  nullable    = true

  validation {
    condition = var.mode_canary == null ? true : try(alltrue([
      for manifest in [jsondecode(var.mode_canary.context_manifest.canonical_utf8)] : alltrue([
        try(
          toset(keys(var.mode_canary)) == toset([
            "schema_version", "context_kind", "application_principal_arn",
            "owner", "context_manifest",
            "delegation_sessions", "resources", "enabled_until",
          ]) && var.mode_canary.schema_version == 2 &&
          contains(["promotion", "readiness"], var.mode_canary.context_kind) &&
          toset(keys(var.mode_canary.owner)) == toset([
            "repository", "run_id", "run_attempt", "generation", "owner_sha256",
          ]) && var.mode_canary.owner.repository == "VINIClUS/CnesData" &&
          var.mode_canary.owner.owner_sha256 == tostring(var.mode_canary.owner.owner_sha256) &&
          can(regex("^[0-9a-f]{64}$", var.mode_canary.owner.owner_sha256)) &&
          alltrue([for key in ["run_id", "run_attempt", "generation"] :
            can(regex("^[1-9][0-9]*$", jsonencode(var.mode_canary.owner[key])))
          ]) &&
          toset(keys(var.mode_canary.context_manifest)) == toset(["canonical_utf8", "sha256"]) &&
          var.mode_canary.context_manifest.canonical_utf8 == format("%s\n", replace(replace(replace(
          jsonencode(manifest), "\\u003c", "<"), "\\u003e", ">"), "\\u0026", "&")) &&
          var.mode_canary.context_manifest.sha256 ==
          sha256(var.mode_canary.context_manifest.canonical_utf8) &&
          toset(keys(manifest)) == toset([
            "schema_version", "context_kind", "owner", "product_source_sha",
            "product_source_closure_sha256",
            "shared_source_sha", "shared_source_closure_sha256", "release_id", "activation_sha256",
            "resources_sha256", "fixture_manifest_sha256", "scenario_plan_sha256",
            "predecessor_terminal_sha256", "admitted_at", "deadline",
          ]) && manifest.schema_version == 2 &&
          manifest.context_kind == var.mode_canary.context_kind &&
          manifest.owner == var.mode_canary.owner &&
          alltrue([for key in ["product_source_sha", "shared_source_sha"] :
            manifest[key] == tostring(manifest[key]) &&
            can(regex("^[0-9a-f]{40}$", manifest[key]))
          ]) &&
          alltrue([for key in [
            "product_source_closure_sha256", "shared_source_closure_sha256", "activation_sha256",
            "resources_sha256", "fixture_manifest_sha256", "scenario_plan_sha256",
            ] : manifest[key] == tostring(manifest[key]) &&
          can(regex("^[0-9a-f]{64}$", manifest[key]))]) &&
          manifest.release_id == tostring(manifest.release_id) &&
          can(regex("^[!-~]+$", manifest.release_id)) &&
          (manifest.predecessor_terminal_sha256 == null ?
            var.mode_canary.context_kind == "promotion" :
            manifest.predecessor_terminal_sha256 ==
            tostring(manifest.predecessor_terminal_sha256) &&
          can(regex("^[0-9a-f]{64}$", manifest.predecessor_terminal_sha256))) &&
          manifest.resources_sha256 == sha256("${jsonencode(var.mode_canary.resources)}\n") &&
          jsonencode(var.mode_canary.delegation_sessions) == jsonencode({
            for alias in local.mode_aliases : alias => sort([
              for operation, entry in local.mode_operations[var.mode_canary.context_kind] : format(
                "mc-%s-%s", entry[0], substr(sha256("${replace(replace(replace(jsonencode(merge(
                  { for key in local.mode_binding_fields : key => manifest[key] }, manifest.owner,
                  { schema_version = 2, operation = operation, phase = entry[2],
                  context_manifest_sha256 = var.mode_canary.context_manifest.sha256 }
                )), "\\u003c", "<"), "\\u003e", ">"), "\\u0026", "&")}\n"), 0, 40)
              ) if entry[1] == alias
          ]) }), false
        ),
        try(
          alltrue([for value in [
            manifest.admitted_at, manifest.deadline, var.mode_canary.enabled_until,
            ] : can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", value)) &&
            formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", value) == value
          ]) &&
          timecmp(manifest.admitted_at, manifest.deadline) < 0 &&
          timecmp(manifest.admitted_at, var.mode_canary.enabled_until) < 0 &&
          (var.mode_canary.context_kind == "readiness" ?
          timecmp(var.mode_canary.enabled_until, manifest.deadline) <= 0 : true), false
        ),
        try(
          toset(keys(var.mode_canary.resources)) == toset([
            "table_arn", "index_arn", "data_bucket_arn", "audit_bucket_arn",
            "cluster_arn", "machine_arn",
            "revisions", "task_role_arns", "execution_role_arn", "network", "log_group_arn",
            "schedule_arns", "alarm_arns", "scope",
            ]) && alltrue([for key, shape in local.mode_resource_shapes :
            toset(keys(var.mode_canary.resources[key])) == toset(shape)
          ]) &&
          var.mode_canary.application_principal_arn == format(
            "arn:aws:iam::%s:role/%s-application", var.account_id, var.name_prefix,
          ) &&
          var.mode_canary.resources.table_arn == var.runtime_grants.table_arn &&
          var.mode_canary.resources.index_arn == "${var.runtime_grants.table_arn}/index/gsi5" &&
          var.mode_canary.resources.data_bucket_arn == var.runtime_grants.data_bucket_arn &&
          var.mode_canary.resources.audit_bucket_arn == var.runtime_grants.audit_bucket_arn &&
          var.mode_canary.resources.machine_arn == var.state_machine_arn &&
          var.mode_canary.resources.log_group_arn == trimsuffix(var.log_group_arn, ":*") &&
          jsonencode(var.mode_canary.resources.task_role_arns) == jsonencode({
            for mode, role in aws_iam_role.task : mode => role.arn
          }) &&
          var.mode_canary.resources.execution_role_arn == aws_iam_role.execution.arn &&
          can(regex("^[0-9a-f]{32}$", var.canary_release.release_id)) &&
          var.mode_canary.resources.scope.tenant_id ==
          "prod-canary-${var.canary_release.release_id}" &&
          jsonencode(var.mode_canary.resources.scope.run_ids) == jsonencode(sort([
            for prefix in ["unit", "recovery-a", "recovery-b"] :
            "${prefix}-${substr(var.mode_canary.owner.owner_sha256, 0, 16)}"
          ])), false
        ),
        try(
          alltrue([for key in [
            "run_ids", "raw_object_keys", "output_object_keys", "audit_object_keys",
            ] :
            length(var.mode_canary.resources.scope[key]) > 0 &&
            jsonencode(var.mode_canary.resources.scope[key]) ==
            jsonencode(sort(distinct(var.mode_canary.resources.scope[key]))) &&
            alltrue([for value in var.mode_canary.resources.scope[key] :
              can(regex("^[A-Za-z0-9._/-]+$", value)) &&
              !contains(split("/", value), "..") && !contains(split("/", value), "")
            ])
          ]) &&
          alltrue([for key in var.mode_canary.resources.scope.raw_object_keys :
            startswith(key, "raw/${var.mode_canary.resources.scope.tenant_id}/")
          ]) &&
          alltrue([for key in var.mode_canary.resources.scope.output_object_keys :
            anytrue([for run in var.mode_canary.resources.scope.run_ids :
              startswith(key, "outputs/${var.mode_canary.resources.scope.tenant_id}/${run}/")
            ])
          ]) &&
          alltrue([for key in var.mode_canary.resources.scope.audit_object_keys :
            can(regex("^audit/(\\.event-id|[0-9]{4}/[0-9]{2}/[0-9]{2})/[0-9a-f]{64}\\.json$", key))
          ]) &&
          length(var.mode_canary.resources.network.public_subnet_ids) > 0 &&
          jsonencode(var.mode_canary.resources.network.public_subnet_ids) ==
          jsonencode(sort(distinct(var.mode_canary.resources.network.public_subnet_ids))), false
        )
      ])
    ]), false)
    error_message = "mode_canary=invalid_contract"
  }
}

locals {
  mode_manifest = try(jsondecode(var.mode_canary.context_manifest.canonical_utf8), null)
  mode_binding_fields = [
    "product_source_sha", "product_source_closure_sha256", "shared_source_sha",
    "shared_source_closure_sha256", "release_id", "activation_sha256", "context_kind",
  ]
  mode_resource_shapes = {
    revisions      = ["audit", "recovery", "unit"]
    task_role_arns = ["audit", "recovery", "unit"]
    network        = ["public_subnet_ids", "security_group_id"]
    schedule_arns  = ["audit", "recovery"]
    alarm_arns     = ["audit_outbox_backlog", "audit_repeated_failure", "recovery_repeated_failure"]
    scope = [
      "audit_object_keys", "output_object_keys", "raw_object_keys", "run_ids", "tenant_id",
    ]
  }
}

variable "name_prefix" {
  description = "Product namespace for processor identities."
  type        = string
  nullable    = false
}

variable "account_id" {
  description = "Own account boundary for ECS task assumption."
  type        = string
  nullable    = false
}

variable "repository_arn" {
  description = "Own private processor repository ARN."
  type        = string
  nullable    = false
}

variable "log_group_arn" {
  description = "Own precreated processor log group ARN."
  type        = string
  nullable    = false
}

variable "state_machine_arn" {
  description = "Exact unqualified own state-machine ARN, or null for the base module."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.state_machine_arn == null ? true : (
      var.state_machine_arn == format(
        "arn:aws:states:us-east-2:%s:stateMachine:%s", var.account_id, var.name_prefix,
      )
    )
    error_message = "state_machine_arn_identity=expected_own_unqualified_machine"
  }
}

variable "runtime_grants" {
  description = "Producer identities for optional runtime application grants."
  type = object({
    table_arn        = string
    index_arns       = object({ gsi1 = string, gsi4 = string, gsi6 = string })
    data_bucket_arn  = string
    audit_bucket_arn = string
    api_role_arn     = string
  })
  default  = null
  nullable = true

  validation {
    condition = (
      (var.runtime_grants == null || var.state_machine_arn != null) &&
      (!var.api_step_functions_enabled ||
      (var.runtime_grants != null && var.state_machine_arn != null))
    )
    error_message = var.runtime_grants == null ? (
      "api_step_functions_enabled=requires_runtime_grants"
      ) : (var.api_step_functions_enabled ? format(
        "%s\n%s",
        "runtime_grants_machine=expected_own_machine",
        "api_step_functions_enabled=requires_runtime_grants",
    ) : "runtime_grants_machine=expected_own_machine")
  }

  validation {
    condition = var.runtime_grants == null ? true : (
      var.runtime_grants.table_arn == format(
        "arn:aws:dynamodb:us-east-2:%s:table/%s-control-plane", var.account_id, var.name_prefix,
      )
    )
    error_message = "runtime_grants_table=expected_own_table"
  }

  validation {
    condition = var.runtime_grants == null ? true : try(alltrue([
      for name in ["gsi1", "gsi4", "gsi6"] :
      var.runtime_grants.index_arns[name] == format(
        "arn:aws:dynamodb:us-east-2:%s:table/%s-control-plane/index/%s",
        var.account_id, var.name_prefix, name,
      )
    ]), false)
    error_message = "runtime_grants_indexes=expected_exact_gsi1_gsi4_gsi6"
  }

  validation {
    condition = var.runtime_grants == null ? true : (
      var.runtime_grants.data_bucket_arn == "arn:aws:s3:::${var.name_prefix}-data" &&
      var.runtime_grants.audit_bucket_arn == "arn:aws:s3:::${var.name_prefix}-audit"
    )
    error_message = "runtime_grants_buckets=expected_own_data_and_audit"
  }

  validation {
    condition = var.runtime_grants == null ? true : try(
      can(regex(
        "^arn:aws:iam::[0-9]{12}:role/([^/*?]+/)*[A-Za-z0-9_+=,.@-]{1,64}$",
        var.runtime_grants.api_role_arn,
      )) &&
      can(regex("^[!-~]+$", var.runtime_grants.api_role_arn)) &&
      split(":", var.runtime_grants.api_role_arn)[4] == var.account_id,
      false,
    )
    error_message = "api_role_arn_identity=expected_own_iam_role"
  }

}

variable "api_step_functions_enabled" {
  description = "Enable API Step Functions grants after processor activation."
  type        = bool
  default     = false
  nullable    = false
}

locals {
  canary_release_id_shape = "^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$"
  canary_role_suffix_max  = 25
}

variable "canary_release" {
  description = "Explicit release activation for canary and promotion identities, or null."
  type = object({
    release_id            = string
    trusted_principal_arn = string
    table_arn             = string
    index_arn             = string
    bucket_arn            = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.canary_release == null ? true : try(
      can(regex(local.canary_release_id_shape, var.canary_release.release_id)), false
    )
    error_message = "canary_release_id=expected_lowercase_alnum_hyphen_max32"
  }

  validation {
    condition = var.canary_release == null ? true : (
      length(var.name_prefix) + local.canary_role_suffix_max <= 64
    )
    error_message = "canary_role_name=expected_max64_chars"
  }

  validation {
    condition     = var.canary_release == null ? true : var.runtime_grants != null
    error_message = "canary_release_runtime_grants=required"
  }

  validation {
    condition = var.canary_release == null ? true : try(
      can(regex(
        "^arn:aws:iam::[0-9]{12}:role/([^/*?]+/)*[A-Za-z0-9_+=,.@-]{1,64}$",
        var.canary_release.trusted_principal_arn,
      )) &&
      can(regex("^[!-~]+$", var.canary_release.trusted_principal_arn)) &&
      split(":", var.canary_release.trusted_principal_arn)[4] == var.account_id,
      false,
    )
    error_message = "canary_principal_arn_identity=expected_own_iam_role"
  }

  validation {
    condition = var.canary_release == null ? true : try(
      var.canary_release.table_arn == format(
        "arn:aws:dynamodb:us-east-2:%s:table/%s-canary", var.account_id, var.name_prefix,
      ) &&
      var.canary_release.index_arn == format(
        "arn:aws:dynamodb:us-east-2:%s:table/%s-canary/index/gsi6",
        var.account_id, var.name_prefix,
      ),
      false,
    )
    error_message = "canary_release_table=expected_own_canary_table_and_gsi6"
  }

  validation {
    condition = var.canary_release == null ? true : (
      var.canary_release.bucket_arn == "arn:aws:s3:::${var.name_prefix}-canary"
    )
    error_message = "canary_release_bucket=expected_own_canary_bucket"
  }
}
