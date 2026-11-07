variable "account_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "An exact reviewed AWS account ID is required."
  }
}

variable "region" {
  type     = string
  nullable = false
  validation {
    condition     = var.region == "us-east-2"
    error_message = "The CnesData runtime contract uses us-east-2."
  }
}

variable "identity" {
  description = "Exact CnesData identity from the reviewed catalog; no other application is adopted."
  type = object({
    trust_anchor_name = string
    role_name         = string
    profile_name      = string
    common_name       = string
    san_uri           = string
    duration_seconds  = number
  })
  nullable = false
  validation {
    condition = try(
      can(regex("^[A-Za-z0-9_+=,.@-]{1,64}$", var.identity.role_name)) &&
      alltrue([for name in [var.identity.profile_name, var.identity.trust_anchor_name] :
      can(regex("^[A-Za-z0-9_-]{1,255}$", name))]) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_.:/@+=,-]{0,63}$", var.identity.common_name)) &&
      can(regex("^[A-Za-z][A-Za-z0-9+.-]*:[!-~]+$", var.identity.san_uri)) &&
      length(regexall("[?*]", var.identity.san_uri)) == 0 &&
      var.identity.duration_seconds >= 900 && var.identity.duration_seconds <= 3600 &&
      floor(var.identity.duration_seconds) == var.identity.duration_seconds,
      false
    )
    error_message = "Exact names/CN/SAN URI and an integer session duration of 900..3600 seconds are required."
  }
}

variable "ca_certificate_pem" {
  description = "One public offline CA certificate. Never a private key, leaf or secret."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\n?$", var.ca_certificate_pem))
    error_message = "Supply exactly one public CA PEM certificate."
  }
}

variable "activation_enabled" {
  description = "Explicit controller decision after live CRL readback and exact-plan audit. Defaults closed."
  type        = bool
  default     = false
  nullable    = false
}

variable "crl_handoff" {
  description = "Offline-validated public evidence; this object does not prove AWS provenance or freshness."
  type = object({
    handoff_version         = number
    operation               = string
    account_id              = string
    region                  = string
    trust_anchor_arn        = string
    crl_id                  = string
    enabled                 = bool
    ca_der_sha256           = string
    ca_pem_sha256           = string
    sha256                  = string
    this_update             = string
    next_update             = string
    crl_number              = string
    revoked_serials         = list(string)
    readback_sha256         = object({ crl = string, trust_anchor = string })
    previous_handoff_sha256 = string
  })
  default  = null
  nullable = true
  validation {
    condition = var.crl_handoff == null ? true : try(
      var.crl_handoff.handoff_version == 1 && var.crl_handoff.enabled &&
      contains(["initialize", "renew"], var.crl_handoff.operation) &&
      (var.crl_handoff.operation == "renew" ? var.crl_handoff.previous_handoff_sha256 != null : var.crl_handoff.previous_handoff_sha256 == null) &&
      var.crl_handoff.account_id == var.account_id && var.crl_handoff.region == var.region &&
      can(regex("^arn:aws:rolesanywhere:us-east-2:[0-9]{12}:trust-anchor/[0-9a-f-]{36}$", var.crl_handoff.trust_anchor_arn)) &&
      can(regex("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", var.crl_handoff.crl_id)) &&
      can(regex("^(0|[1-9][0-9]*)$", var.crl_handoff.crl_number)) &&
      alltrue([for serial in var.crl_handoff.revoked_serials : can(regex("^[1-9][0-9]*$", serial))]) &&
      length(distinct(var.crl_handoff.revoked_serials)) == length(var.crl_handoff.revoked_serials) &&
      alltrue([for digest in [var.crl_handoff.ca_der_sha256, var.crl_handoff.ca_pem_sha256,
        var.crl_handoff.sha256, var.crl_handoff.readback_sha256.crl, var.crl_handoff.readback_sha256.trust_anchor] :
      can(regex("^[0-9a-f]{64}$", digest))]) &&
      (var.crl_handoff.previous_handoff_sha256 == null ? true : can(regex("^[0-9a-f]{64}$", var.crl_handoff.previous_handoff_sha256))) &&
      alltrue([for date in [var.crl_handoff.this_update, var.crl_handoff.next_update] :
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", date))]) &&
      timecmp(var.crl_handoff.this_update, var.crl_handoff.next_update) < 0,
      false
    )
    error_message = "CRL handoff must contain enabled, account-bound, canonical public metadata."
  }
}

variable "crl_handoff_sha256" {
  description = "SHA256 of the helper's canonical crl_handoff object, bound to audited inputs/plan."
  type        = string
  default     = null
  nullable    = true
}
