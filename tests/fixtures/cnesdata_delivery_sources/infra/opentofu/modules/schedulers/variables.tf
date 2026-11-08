variable "name_prefix" {
  description = "Product namespace for task families, roles, schedules and alarms."
  type        = string
  nullable    = false
}

variable "account_id" {
  description = "Production account ID bound into Scheduler trust and revision ARNs."
  type        = string
  nullable    = false
}

variable "cluster_arn" {
  description = "Own ECS processor cluster ARN targeted by both schedules."
  type        = string
  nullable    = false
}

variable "recovery_task_definition_arn" {
  description = "Exact recovery revision run by the recovery schedule; null creates no schedule."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.recovery_task_definition_arn == null ? true : can(regex(
      "^arn:aws:ecs:us-east-2:${var.account_id}:task-definition/${var.name_prefix}-processor-recovery:[1-9][0-9]*$",
      var.recovery_task_definition_arn,
    ))
    error_message = "recovery_revision=expected_own_recovery_family_positive_decimal_revision"
  }
}

variable "audit_task_definition_arn" {
  description = "Exact audit revision run by the dispatch schedule; null creates no schedule."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.audit_task_definition_arn == null ? true : can(regex(
      "^arn:aws:ecs:us-east-2:${var.account_id}:task-definition/${var.name_prefix}-processor-audit:[1-9][0-9]*$",
      var.audit_task_definition_arn,
    ))
    error_message = "audit_revision=expected_own_audit_family_positive_decimal_revision"
  }
}

variable "task_role_arns" {
  description = "Existing task role ARNs keyed by processor mode; recovery and audit are passed."
  type        = map(string)
  nullable    = false

  validation {
    condition     = alltrue([for mode in ["recovery", "audit"] : contains(keys(var.task_role_arns), mode)])
    error_message = "task_role_arns=expected_recovery_and_audit"
  }

  validation {
    condition     = length(distinct([for mode in ["recovery", "audit"] : try(var.task_role_arns[mode], mode)])) == 2
    error_message = "task_role_arns=expected_distinct_role_per_mode"
  }
}

variable "execution_role_arn" {
  description = "Shared execution role ARN passed to both modes."
  type        = string
  nullable    = false
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the RunTask network configuration."
  type        = list(string)
  nullable    = false
}

variable "security_group_id" {
  description = "Zero-ingress task security group ID."
  type        = string
  nullable    = false
}

variable "alarm_actions" {
  description = "Action ARNs (at most 5) run when a scheduler alarm enters ALARM; empty is silent."
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = length(var.alarm_actions) <= 5
    error_message = "alarm_actions=expected_at_most_5"
  }
}
