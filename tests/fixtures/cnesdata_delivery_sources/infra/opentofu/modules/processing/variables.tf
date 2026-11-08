variable "image_digest" {
  description = "Processor image digest supplied by the production root."
  type        = string
  nullable    = true

  validation {
    condition = var.image_digest == null ? true : can(
      regex("^sha256:[0-9a-f]{64}$", var.image_digest)
    )
    error_message = "image_digest_shape=expected_null_or_sha256_lower_hex64"
  }
}

variable "name_prefix" {
  description = "Product namespace for processor task families."
  type        = string
  nullable    = false
}

variable "repository_uri" {
  description = "Own private processor repository URI."
  type        = string
  nullable    = false
}

variable "task_role_arns" {
  description = "Existing task role ARNs keyed by processor mode."
  type        = map(string)
  nullable    = false
}

variable "execution_role_arn" {
  description = "Shared execution role ARN for processor tasks."
  type        = string
  nullable    = false
}

variable "log_group_name" {
  description = "Precreated processor CloudWatch log group name."
  type        = string
  nullable    = false
}

variable "control_plane_table" {
  description = "Control-plane table name shared by processor modes."
  type        = string
  nullable    = false
}

variable "data_bucket" {
  description = "Data bucket name for unit and recovery modes."
  type        = string
  nullable    = false
}

variable "audit_bucket" {
  description = "Audit bucket name for outbox dispatch."
  type        = string
  nullable    = false
}

variable "audit_retention_days" {
  description = "Audit bucket COMPLIANCE retention in days."
  type        = number
  nullable    = false
}

variable "state_machine_arn" {
  description = "Reserved unqualified production state-machine ARN."
  type        = string
  nullable    = false
}

variable "public_subnet_ids" {
  description = "Actual public subnet IDs for unit and recovery RunTask inputs."
  type        = list(string)
  nullable    = false
}

variable "security_group_id" {
  description = "Actual zero-ingress task security group ID."
  type        = string
  nullable    = false
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
        split(":", var.state_machine_arn)[4],
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
        "${var.name_prefix}-processor-unit",
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
        split(":", arn)[4] == split(":", var.state_machine_arn)[4],
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
        "${var.name_prefix}-processor-unit",
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

variable "step_functions_role_arn" {
  description = "Step Functions execution role ARN required for active routing."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.processor_active_unit_task_definition_arn == null || var.step_functions_role_arn != null
    )
    error_message = "step_functions_role_required=expected_role_for_active_machine"
  }

  validation {
    condition = !var.enable_step_functions_iam ? true : try(
      var.step_functions_role_arn == format(
        "arn:aws:iam::%s:role/%s-step-functions",
        split(":", var.state_machine_arn)[4], var.name_prefix,
      ),
      false,
    )
    error_message = "step_functions_iam_role_arn=expected_own_role_arn"
  }
}

variable "step_functions_role_id" {
  description = "Step Functions role name for optional ECS integration grants."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = !var.enable_step_functions_iam ? true : (
      var.step_functions_role_id == "${var.name_prefix}-step-functions"
    )
    error_message = "step_functions_iam_role_id=expected_own_role_name"
  }
}

variable "enable_step_functions_iam" {
  description = "Enable ECS integration grants using a known composition switch."
  type        = bool
  default     = false
  nullable    = false
}

variable "canary_storage_enabled" {
  description = "Provision the persistent canary table and bucket, independent of any release."
  type        = bool
  default     = false
  nullable    = false
}

variable "canary_verifier_role_id" {
  description = "Canary verifier role name receiving the audit RunTask grant, or null."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.canary_verifier_role_id == null ? true : (
      var.canary_verifier_role_id == "${var.name_prefix}-canary-verifier"
    )
    error_message = "canary_verifier_role_id=expected_own_role_name"
  }
}
