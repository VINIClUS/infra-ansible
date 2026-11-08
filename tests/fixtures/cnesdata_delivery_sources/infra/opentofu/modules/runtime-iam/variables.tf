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
