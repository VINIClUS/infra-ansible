variable "shared_outputs" {
  description = "Versioned outputs consumed from the shared personal-infra state."
  type = object({
    schema_version = number
    account_id     = string
    kms_key_arn    = string
    roles_anywhere = object({
      api_role_arn     = string
      profile_arn      = string
      trust_anchor_arn = string
      crl = object({
        crl_id      = string
        enabled     = bool
        next_update = string
        sha256      = string
      })
    })
    github = object({
      infrastructure_plan_role_arn   = string
      infrastructure_deploy_role_arn = string
      host_deploy_role_arn           = string
    })
    budget_freeze = object({
      budget_arn = string
      action_arn = string
      policy_arn = string
    })
    storage = object({
      state_bucket_name    = string
      state_bucket_arn     = string
      evidence_bucket_name = string
      evidence_bucket_arn  = string
    })
    account_baseline = object({
      s3_public_access_block = object({
        block_public_acls       = bool
        block_public_policy     = bool
        ignore_public_acls      = bool
        restrict_public_buckets = bool
      })
    })
  })
  nullable = false

  validation {
    condition     = var.shared_outputs.schema_version == 2
    error_message = "shared_outputs.schema_version must be 2."
  }

  validation {
    condition     = can(regex("^[0-9]{12}$", var.shared_outputs.account_id))
    error_message = "shared_outputs.account_id must contain exactly 12 digits."
  }

  validation {
    condition = alltrue([
      for arn in [
        var.shared_outputs.kms_key_arn,
        var.shared_outputs.roles_anywhere.api_role_arn,
        var.shared_outputs.roles_anywhere.profile_arn,
        var.shared_outputs.roles_anywhere.trust_anchor_arn,
        var.shared_outputs.github.infrastructure_plan_role_arn,
        var.shared_outputs.github.infrastructure_deploy_role_arn,
        var.shared_outputs.github.host_deploy_role_arn,
        var.shared_outputs.budget_freeze.budget_arn,
        var.shared_outputs.budget_freeze.action_arn,
        var.shared_outputs.budget_freeze.policy_arn,
        var.shared_outputs.storage.state_bucket_arn,
        var.shared_outputs.storage.evidence_bucket_arn,
        ] : can(regex(
          "^arn:(aws|aws-us-gov|aws-cn):[a-z0-9-]+:[a-z0-9-]*:([0-9]{12})?:.+$",
          arn,
      ))
    ])
    error_message = "Every shared_outputs ARN must use a valid AWS ARN shape."
  }

  validation {
    condition = (
      length(trimspace(var.shared_outputs.roles_anywhere.crl.crl_id)) > 0 &&
      can(regex("^[0-9a-f]{64}$", var.shared_outputs.roles_anywhere.crl.sha256))
    )
    error_message = "Roles Anywhere CRL evidence requires an ID and lowercase SHA-256."
  }

  validation {
    condition     = var.shared_outputs.roles_anywhere.crl.enabled != null
    error_message = "Roles Anywhere CRL enabled status must be a boolean."
  }

  validation {
    condition = can(
      formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.shared_outputs.roles_anywhere.crl.next_update)
    )
    error_message = "Roles Anywhere CRL next_update must be an RFC 3339 timestamp."
  }

  validation {
    condition = alltrue([
      for bucket in [
        var.shared_outputs.storage.state_bucket_name,
        var.shared_outputs.storage.evidence_bucket_name,
      ] : can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", bucket))
    ])
    error_message = "Shared storage bucket names must use the approved S3 name shape."
  }

  validation {
    condition = try(alltrue([
      for enabled in [
        var.shared_outputs.account_baseline.s3_public_access_block.block_public_acls,
        var.shared_outputs.account_baseline.s3_public_access_block.block_public_policy,
        var.shared_outputs.account_baseline.s3_public_access_block.ignore_public_acls,
        var.shared_outputs.account_baseline.s3_public_access_block.restrict_public_buckets,
      ] : enabled == true
    ]), false)
    error_message = "Account S3 Block Public Access evidence must enable all four flags."
  }
}

variable "image_digest" {
  description = "Optional processor image digest for staged task registration."
  type        = string
  default     = null
  nullable    = true
}

variable "canary_release_id" {
  description = "Derived 32-hex canary identity bound to the full candidate release."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.canary_release_id == null ? true : can(regex(
      "^[0-9a-f]{32}$", var.canary_release_id,
    ))
    error_message = "canary_release_id=expected_derived_32_hex"
  }

  validation {
    condition = (
      (var.canary_release_id == null) == (var.canary_trusted_principal_arn == null) &&
      var.canary_storage_enabled == (var.canary_release_id != null)
    )
    error_message = "canary_inputs=expected_joint_activation_or_null_bootstrap"
  }
}

variable "canary_trusted_principal_arn" {
  description = "Governed same-account canary principal, or null before Phase A."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.canary_trusted_principal_arn == null ? true : try(
      can(regex(
        "^arn:aws:iam::[0-9]{12}:role/([^/*?]+/)*[A-Za-z0-9_+=,.@-]{1,64}$",
        var.canary_trusted_principal_arn,
      )) &&
      split(":", var.canary_trusted_principal_arn)[4] == var.shared_outputs.account_id,
      false,
    )
    error_message = "canary_principal=expected_own_iam_role"
  }
}

variable "canary_storage_enabled" {
  description = "Explicit protected canary storage activation; disabled during bootstrap."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.canary_storage_enabled || var.image_digest != null
    error_message = "canary_storage=requires_image_digest"
  }
}

locals {
  processor_unit_revision_shape = join("", [
    "^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:",
    "task-definition/[A-Za-z0-9_-]+:[^:]+$",
  ])
}

variable "processor_active_unit_task_definition_arn" {
  description = "Explicit unit routing revision, separate from the registered candidate."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.processor_active_unit_task_definition_arn == null ? true : (
      can(regex(
        local.processor_unit_revision_shape,
        var.processor_active_unit_task_definition_arn,
      ))
    )
    error_message = "task_definition_arn_shape=expected_qualified_ecs_task_definition"
  }

  validation {
    condition = var.processor_active_unit_task_definition_arn == null ? true : (
      !can(regex(
        local.processor_unit_revision_shape,
        var.processor_active_unit_task_definition_arn,
        )) || try(
        split(":", var.processor_active_unit_task_definition_arn)[4] ==
        var.shared_outputs.account_id,
        false,
      )
    )
    error_message = "task_definition_arn_account=expected_production_account"
  }

  validation {
    condition = var.processor_active_unit_task_definition_arn == null ? true : (
      !can(regex(
        local.processor_unit_revision_shape,
        var.processor_active_unit_task_definition_arn,
        )) || try(
        split(":", var.processor_active_unit_task_definition_arn)[3] == "us-east-2",
        false,
      )
    )
    error_message = "task_definition_arn_region=expected_us_east_2"
  }

  validation {
    condition = var.processor_active_unit_task_definition_arn == null ? true : (
      !can(regex(
        local.processor_unit_revision_shape,
        var.processor_active_unit_task_definition_arn,
        )) || try(
        split("/", split(":", var.processor_active_unit_task_definition_arn)[5])[1] ==
        "${local.name_prefix}-processor-unit",
        false,
      )
    )
    error_message = "task_definition_arn_family=expected_unit_family"
  }

  validation {
    condition = var.processor_active_unit_task_definition_arn == null ? true : (
      !can(regex(
        local.processor_unit_revision_shape,
        var.processor_active_unit_task_definition_arn,
        )) || try(
        can(regex("^[1-9][0-9]*$", split(":", var.processor_active_unit_task_definition_arn)[6])),
        false,
      )
    )
    error_message = "task_definition_arn_revision=expected_positive_decimal"
  }

  validation {
    condition = var.processor_active_unit_task_definition_arn == null ? true : contains(
      var.processor_retained_unit_task_definition_arns,
      var.processor_active_unit_task_definition_arn,
    )
    error_message = "active_must_be_retained=expected_authorized_unit_revision"
  }
}

variable "processor_retained_unit_task_definition_arns" {
  description = "Exact unit revisions retained for promotion, drain and rollback."
  type        = set(string)
  default     = []
  nullable    = false

  validation {
    condition = alltrue([
      for arn in var.processor_retained_unit_task_definition_arns :
      can(regex(
        local.processor_unit_revision_shape,
        arn,
      ))
    ])
    error_message = "task_definition_arn_shape=expected_qualified_ecs_task_definition"
  }

  validation {
    condition = alltrue([
      for arn in var.processor_retained_unit_task_definition_arns :
      !can(regex(
        local.processor_unit_revision_shape,
        arn,
        )) || try(
        split(":", arn)[4] == var.shared_outputs.account_id,
        false,
      )
    ])
    error_message = "task_definition_arn_account=expected_production_account"
  }

  validation {
    condition = alltrue([
      for arn in var.processor_retained_unit_task_definition_arns :
      !can(regex(
        local.processor_unit_revision_shape,
        arn,
        )) || try(
        split(":", arn)[3] == "us-east-2",
        false,
      )
    ])
    error_message = "task_definition_arn_region=expected_us_east_2"
  }

  validation {
    condition = alltrue([
      for arn in var.processor_retained_unit_task_definition_arns :
      !can(regex(
        local.processor_unit_revision_shape,
        arn,
        )) || try(
        split("/", split(":", arn)[5])[1] ==
        "${local.name_prefix}-processor-unit",
        false,
      )
    ])
    error_message = "task_definition_arn_family=expected_unit_family"
  }

  validation {
    condition = alltrue([
      for arn in var.processor_retained_unit_task_definition_arns :
      !can(regex(
        local.processor_unit_revision_shape,
        arn,
        )) || try(
        can(regex("^[1-9][0-9]*$", split(":", arn)[6])),
        false,
      )
    ])
    error_message = "task_definition_arn_revision=expected_positive_decimal"
  }
}

variable "scheduler_recovery_task_definition_arn" {
  description = "Exact recovery revision for its schedule; null creates no schedule."
  type        = string
  default     = null
  nullable    = true
}

variable "scheduler_audit_task_definition_arn" {
  description = "Exact audit revision for its schedule; null creates no schedule."
  type        = string
  default     = null
  nullable    = true
}
