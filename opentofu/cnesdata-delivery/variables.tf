variable "application_promotion" {
  description = "Private reviewed application principal configuration. Null creates no application role or operational capability."
  # Keep the raw shape: object coercion would silently discard unreviewed fields.
  type     = any
  default  = null
  nullable = true
  validation {
    condition = var.application_promotion == null ? true : try(
      var.github_delivery != null &&
      contains([toset(["role_name", "workflow_sha", "source_closure_sha256", "enabled_until", "delegations"]),
      toset(["role_name", "workflow_sha", "source_closure_sha256", "enabled_until", "delegations", "predecessor_read"])], toset(keys(var.application_promotion))) &&
      can(regex("^cnesdata-[a-z0-9-]+-application$", var.application_promotion.role_name)) &&
      can(regex("^[0-9a-f]{40}$", var.application_promotion.workflow_sha)) &&
      can(regex("^[0-9a-f]{64}$", var.application_promotion.source_closure_sha256)) &&
      can(timecmp(var.application_promotion.enabled_until, "1970-01-01T00:00:00Z")) &&
      toset(keys(var.application_promotion.delegations)) == toset(["observer", "normal", "recovery", "seeder", "verifier", "fence_operator", "mode_seed", "mode_dispatch", "mode_audit_launch", "mode_observe"]) &&
      length(distinct(values(var.application_promotion.delegations))) == 10 &&
      alltrue([for role, arn in var.application_promotion.delegations :
    arn == "arn:aws:iam::${var.account_id}:role/cnesdata-prod-${lookup({ observer = "static-observer", normal = "static-normal", recovery = "static-recovery", seeder = "canary-seeder", verifier = "canary-verifier", fence_operator = "promotion-fence-operator", mode_seed = "mode-seed", mode_dispatch = "mode-dispatch", mode_audit_launch = "mode-audit-launch", mode_observe = "mode-observe" }, role, "invalid")}"]), false)
    error_message = "Application requires the existing provider, immutable producer, expiry and ten exact same-product delegation ARNs."
  }
  validation {
    condition = try(var.application_promotion.predecessor_read, null) == null ? true : try(
      toset(keys(var.application_promotion.predecessor_read)) == toset(["protocol", "source_sha", "run_id", "run_attempt", "status", "purpose"]) &&
      can(regex("^[1-9][0-9]*$", jsonencode(var.application_promotion.predecessor_read.run_id))) &&
      can(regex("^[1-9][0-9]*$", jsonencode(var.application_promotion.predecessor_read.run_attempt))) &&
      can(regex("^[0-9a-f]{40}$", var.application_promotion.predecessor_read.source_sha)) &&
      var.application_promotion.predecessor_read.run_id >= 1 &&
      var.application_promotion.predecessor_read.run_id == floor(var.application_promotion.predecessor_read.run_id) &&
      var.application_promotion.predecessor_read.run_attempt >= 1 &&
      var.application_promotion.predecessor_read.run_attempt == floor(var.application_promotion.predecessor_read.run_attempt) &&
      ((var.application_promotion.predecessor_read.protocol == "legacy-infra" &&
        contains(["planned", "applied"], var.application_promotion.predecessor_read.status) &&
        contains(["acm-certificate", "bootstrap", "phase-a"], var.application_promotion.predecessor_read.purpose)) ||
        (var.application_promotion.predecessor_read.protocol == "lifecycle" &&
          var.application_promotion.predecessor_read.status == "terminal" &&
    var.application_promotion.predecessor_read.purpose == "application")), false)
    error_message = "Predecessor read requires one exact original legacy or lifecycle run; no free keys, prefixes or wildcard authority."
  }
}

variable "account_id" {
  type     = string
  nullable = false
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "An exact reviewed AWS account ID is required."
  }
}

variable "github_delivery" {
  description = "Reviewed catalog configuration; null keeps both gates absent. Provider is shared/external. No caller input controls this object."
  type = object({
    provider_arn         = string
    provider_client_ids  = list(string)
    provider_thumbprints = list(string)
    plan_role_name       = string
    deploy_role_name     = string
    plan_workflow_sha    = string
    deploy_workflow_sha  = string
    enabled_until        = string
    state_bucket_arn     = string
    state_kms_arn        = string
    evidence_bucket_arn  = string
    evidence_kms_arn     = string
    evidence_prefix      = string
    read_resource_arns   = list(string)
    product_permissions = list(object({
      actions   = list(string)
      resources = list(string)
    }))
    pass_roles = list(object({ arn = string, service = string }))
    activation_read = optional(object({
      bucket_arn         = string
      cipher_kms_key_arn = string
      keys               = object({ payload = string, signature = string, receipt = string })
    }), null)
  })
  default  = null
  nullable = true
  validation {
    condition = var.github_delivery == null ? true : try(
      var.github_delivery.provider_arn == "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com" &&
      contains(var.github_delivery.provider_client_ids, "sts.amazonaws.com") &&
      length(var.github_delivery.provider_thumbprints) > 0 &&
      alltrue([for value in var.github_delivery.provider_thumbprints : can(regex("^[0-9a-f]{40}$", value))]) &&
      can(regex("^cnesdata-[a-z0-9-]+-plan$", var.github_delivery.plan_role_name)) &&
      can(regex("^cnesdata-[a-z0-9-]+-deploy$", var.github_delivery.deploy_role_name)) &&
      alltrue([for value in [var.github_delivery.plan_workflow_sha, var.github_delivery.deploy_workflow_sha] : can(regex("^[0-9a-f]{40}$", value))]) &&
      can(timecmp(var.github_delivery.enabled_until, "1970-01-01T00:00:00Z")) &&
      alltrue([for arn in [var.github_delivery.state_bucket_arn, var.github_delivery.evidence_bucket_arn] : can(regex("^arn:aws:s3:::[a-z0-9.-]+$", arn))]) &&
      alltrue([for arn in [var.github_delivery.state_kms_arn, var.github_delivery.evidence_kms_arn] : can(regex("^arn:aws:kms:us-east-2:${var.account_id}:key/[0-9a-f-]{36}$", arn))]) &&
      startswith(var.github_delivery.evidence_prefix, "cnesdata/prod/") &&
      !strcontains(var.github_delivery.evidence_prefix, "..") &&
      length(regexall("[?*]", var.github_delivery.evidence_prefix)) == 0 &&
      alltrue([for arn in var.github_delivery.read_resource_arns :
        length(regexall("[?*]", arn)) == 0 &&
      (strcontains(arn, ":${var.account_id}:") || startswith(arn, "arn:aws:s3:::cnesdata-"))]) &&
      alltrue([for statement in var.github_delivery.product_permissions : length(statement.actions) > 0 && length(statement.resources) > 0 &&
        alltrue([for action in statement.actions : contains(local.delivery_product_writes, action)]) &&
        alltrue([for arn in statement.resources : startswith(arn, "arn:aws:") &&
          (strcontains(arn, ":${var.account_id}:") || startswith(arn, "arn:aws:s3:::cnesdata-")) &&
          length(regexall("[?*]", arn)) == 0 && !strcontains(arn, "cnesdata-delivery") &&
          !strcontains(arn, "limnopulse") && !strcontains(arn, "bootstrap") &&
          !contains(["arn:aws:iam::${var.account_id}:role/${var.github_delivery.plan_role_name}", "arn:aws:iam::${var.account_id}:role/${var.github_delivery.deploy_role_name}"], arn) &&
      (!startswith(arn, "arn:aws:iam:") || can(regex("^arn:aws:iam::${var.account_id}:role/cnesdata-[a-z0-9-]+$", arn)))])]) &&
      alltrue([for value in var.github_delivery.pass_roles :
        can(regex("^arn:aws:iam::${var.account_id}:role/cnesdata-[a-z0-9-]+$", value.arn)) &&
    contains(["ecs-tasks.amazonaws.com", "lambda.amazonaws.com", "scheduler.amazonaws.com", "states.amazonaws.com"], value.service)]), false)
    error_message = "Exact shared provider, reviewed immutable gates, product-only resources, named actions and bounded trust are required; no wildcard writes or cross-assume."
  }
  validation {
    condition = var.github_delivery == null || var.github_delivery.activation_read == null ? true : try(
      can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.github_delivery.activation_read.bucket_arn)) &&
      can(regex("^arn:aws:kms:us-east-2:${var.account_id}:key/[0-9a-f-]{36}$", var.github_delivery.activation_read.cipher_kms_key_arn)) &&
      length(distinct(values(var.github_delivery.activation_read.keys))) == 3 &&
      alltrue([for key in values(var.github_delivery.activation_read.keys) :
        length(key) > 0 && length(key) <= 1024 && !startswith(key, "/") && !strcontains(key, "..") &&
        length(regexall("[?*]", key)) == 0 && !contains(local.delivery_state_keys, key) &&
    !startswith(key, "${var.github_delivery.evidence_prefix}lifecycle/")]), false)
    error_message = "Activation read ceiling needs one exact bucket and cipher key and three distinct wildcard-free keys disjoint from state, lease and lifecycle evidence."
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

variable "ext2_enabled" {
  description = "Explicit owner-reviewed delivery-only EXT2 creation. Never enables a product apply."
  type        = bool
  default     = false
  nullable    = false
}

variable "ext2" {
  description = "Owner-frozen finite signing/evidence contract; external bucket and cipher key are never adopted."
  type = object({
    workflow_sha        = string
    enabled_until       = string
    retain_until        = string
    admin_arns          = list(string)
    bucket_arn          = string
    cipher_kms_key_arn  = string
    current_object_arns = list(string)
    history_object_arns = list(string)
  })
  default  = null
  nullable = true
  validation {
    condition = var.ext2 == null ? !var.ext2_enabled : try(
      can(regex("^[0-9a-f]{40}$", var.ext2.workflow_sha)) &&
      can(regex("^arn:aws:s3:::[a-z0-9.-]+$", var.ext2.bucket_arn)) &&
      can(regex("^arn:aws:kms:us-east-2:${var.account_id}:key/[0-9a-f-]{36}$", var.ext2.cipher_kms_key_arn)) &&
      alltrue([for date in [var.ext2.enabled_until, var.ext2.retain_until] : can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", date)) && can(timecmp(date, "1970-01-01T00:00:00Z"))]) &&
      length(var.ext2.admin_arns) > 0 && length(var.ext2.admin_arns) <= 4 &&
      length(distinct(var.ext2.admin_arns)) == length(var.ext2.admin_arns) &&
      alltrue([for arn in var.ext2.admin_arns : can(regex("^arn:aws:iam::${var.account_id}:role/[A-Za-z0-9_+=,.@/-]+$", arn)) && arn != "arn:aws:iam::${var.account_id}:role/cnesdata-delivery-ext2-gate"]) &&
      length(var.ext2.current_object_arns) == 3 && length(var.ext2.history_object_arns) <= 9 &&
      length(distinct(concat(var.ext2.current_object_arns, var.ext2.history_object_arns))) == 3 + length(var.ext2.history_object_arns) &&
      alltrue([for arn in var.ext2.current_object_arns : startswith(arn, "${var.ext2.bucket_arn}/cnesdata/prod/ext2/current/")]) &&
      alltrue([for arn in var.ext2.history_object_arns : startswith(arn, "${var.ext2.bucket_arn}/cnesdata/prod/ext2/")]) &&
    alltrue([for arn in concat(var.ext2.current_object_arns, var.ext2.history_object_arns) : length(regexall("[?*]", arn)) == 0 && !strcontains(arn, "..") && !endswith(arn, "/")]), false)
    error_message = "EXT2 requires finite exact private object ARNs, a full same-account regional cipher CMK, immutable reusable SHA, absolute owner dates and named owner administrators."
  }
}
variable "host_gate" {
  description = "EXT3 exact read-only host input capability. Null leaves the existing seed unchanged; live claims/readbacks remain a Ready gate."
  type = object({
    workflow_sha       = string
    objects            = list(object({ arn = string, version = string }))
    ssm_parameter_arns = list(string)
    ssm_key_arn        = string
    decrypt_keys       = list(object({ arn = string, object_arns = list(string) }))
  })
  default = null
  validation {
    condition = var.host_gate == null ? true : (
      can(regex("^[0-9a-f]{40}$", var.host_gate.workflow_sha)) &&
      length(var.host_gate.objects) > 0 &&
      length(var.host_gate.ssm_parameter_arns) == 3 &&
      length(distinct(var.host_gate.ssm_parameter_arns)) == 3 &&
      alltrue([for object in var.host_gate.objects :
        can(regex("^arn:aws:s3:::[a-z0-9.-]+/cnesdata/[^*?]+$", object.arn)) &&
        length(object.version) > 0 && !contains(["null", "*"], object.version)
      ]) &&
      alltrue([for arn in var.host_gate.ssm_parameter_arns :
        can(regex("^arn:aws:ssm:[a-z0-9-]+:[0-9]{12}:parameter/cnesdata/deploy/(ssh-key|cloudflare-client-id|cloudflare-client-secret)$", arn))
      ]) &&
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", var.host_gate.ssm_key_arn)) &&
      alltrue([for key in var.host_gate.decrypt_keys :
        can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", key.arn)) &&
        length(key.object_arns) > 0 &&
        alltrue([for arn in key.object_arns : contains([for object in var.host_gate.objects : object.arn], arn)])
      ])
    )
    error_message = "EXT3 requires an immutable workflow, exact versioned CnesData objects, three deployment SSM leaves, and exact KMS encryption contexts."
  }
}
