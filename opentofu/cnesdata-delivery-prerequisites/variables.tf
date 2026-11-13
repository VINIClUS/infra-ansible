variable "account_id" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account id."
  }
}

variable "region" {
  type     = string
  nullable = false

  validation {
    condition     = var.region == "us-east-2"
    error_message = "region must be us-east-2."
  }
}

variable "tags" {
  type     = map(string)
  default  = {}
  nullable = false
}

variable "github_oidc_enabled" {
  description = "Creates the single shared GitHub OIDC provider. Off by default."
  type        = bool
  default     = false
  nullable    = false
}

variable "evidence_enabled" {
  description = "Creates the Object Lock evidence bucket and its dedicated CMK. Off by default."
  type        = bool
  default     = false
  nullable    = false
}

variable "evidence_bucket_name" {
  description = "Globally unique evidence bucket name; required when evidence_enabled."
  type        = string
  default     = null

  validation {
    condition = var.evidence_bucket_name == null || (
      can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.evidence_bucket_name)) &&
      !strcontains(var.evidence_bucket_name, "..")
    )
    error_message = "evidence_bucket_name must be a valid S3 bucket name."
  }
}
