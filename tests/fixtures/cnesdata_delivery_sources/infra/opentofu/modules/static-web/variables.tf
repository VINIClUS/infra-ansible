variable "bucket_name" {
  type     = string
  nullable = false

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name=invalido"
  }
}

variable "certificate_arn" {
  type     = string
  nullable = false

  validation {
    condition = (
      can(
        regex(
          join("", [
            "^arn:aws:acm:us-east-1:[0-9]{12}:certificate/",
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
          ]),
          var.certificate_arn
        )
      )
    )
    error_message = "certificate_arn=invalido"
  }
}

variable "cognito" {
  type = object({
    issuer_url          = string
    hosted_login_origin = string
    client_id           = string
  })
  nullable = false

  validation {
    condition = (
      can(
        regex(
          "^https://cognito-idp\\.us-east-2\\.amazonaws\\.com/us-east-2_[A-Za-z0-9]+/?$",
          var.cognito.issuer_url
        )
      ) &&
      can(
        regex(
          "^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.auth\\.us-east-2\\.amazoncognito\\.com/?$",
          var.cognito.hosted_login_origin
        )
      ) &&
      length(trimspace(var.cognito.client_id)) > 0
    )
    error_message = "cognito=invalido"
  }
}

variable "serving_origin" {
  type     = string
  nullable = false

  validation {
    condition = (
      can(
        regex(
          "^https://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+/?$",
          var.serving_origin
        )
      )
    )
    error_message = "serving_origin=invalido"
  }
}

variable "csp_mode" {
  type     = string
  nullable = false

  validation {
    condition     = contains(["report_only", "enforce"], var.csp_mode)
    error_message = "csp_mode=invalido"
  }
}

variable "certificate_domain_validated" {
  type     = bool
  nullable = false
}

variable "waf_ruleset" {
  type     = string
  nullable = false

  validation {
    condition     = var.waf_ruleset == "baseline_v1"
    error_message = "waf_ruleset=invalido"
  }
}
