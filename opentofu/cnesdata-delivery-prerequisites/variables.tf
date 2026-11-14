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

variable "github_oidc_thumbprints" {
  description = "Published GitHub Actions intermediate CA thumbprints (GitHub changelog 2023-06-27)."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
  nullable    = false

  validation {
    condition = length(var.github_oidc_thumbprints) > 0 && alltrue([
      for value in var.github_oidc_thumbprints : can(regex("^[0-9a-f]{40}$", value))
    ])
    error_message = "github_oidc_thumbprints must be a non-empty list of 40-hex lowercase values."
  }
}
