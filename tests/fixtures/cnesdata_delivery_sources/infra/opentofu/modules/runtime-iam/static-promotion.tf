variable "static_promotion" {
  description = "Closed static capability contract, or null to create no static identity."
  type        = any
  default     = null
  nullable    = true
  validation {
    condition = var.static_promotion == null ? true : try(alltrue([
      (try(alltrue([
        toset(keys(var.static_promotion.application_promotion)) == setunion(toset([
          "fragment_version", "account_id", "region", "application_role_arn",
          "application_role_name",
          "producer", "caller_by_purpose", "provider_arn", "lease", "evidence", "delegations",
          "trust_sha256", "policy_sha256", "enabled_until",
          ]), contains(keys(var.static_promotion.application_promotion), "predecessor_reads") ?
        toset(["predecessor_reads"]) : toset([])),
        var.static_promotion.application_promotion.fragment_version == 4 &&
        var.static_promotion.application_promotion.account_id == var.account_id &&
        var.static_promotion.application_promotion.region == "us-east-2" && var.name_prefix ==
        "cnesdata-prod",
        var.static_promotion.application_promotion.application_role_name ==
        "${var.name_prefix}-application" &&
        var.static_promotion.application_promotion.application_role_arn ==
        "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-application",
        var.static_promotion.application_promotion.provider_arn ==
        "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com",
        toset(keys(var.static_promotion.application_promotion.producer)) == toset([
          "repository", "workflow_path", "workflow_sha", "source_closure_sha256",
        ]) && var.static_promotion.application_promotion.producer.repository ==
        "VINIClUS/infra-ansible" &&
        var.static_promotion.application_promotion.producer.workflow_path ==
        ".github/workflows/reusable-cnesdata-application-gate.yml" &&
        var.static_promotion.application_promotion.producer.workflow_sha ==
        var.static_promotion.binding.shared_source_sha,
        jsonencode(var.static_promotion.application_promotion.caller_by_purpose) == jsonencode({
          promotion = {
            repository    = "VINIClUS/CnesData",
            workflow_path = ".github/workflows/promote-production.yml",
            ref           = "refs/heads/develop", environment = "production"
          }
          mode-readiness-drill = {
            repository    = "VINIClUS/CnesData",
            workflow_path = ".github/workflows/readiness-production.yml",
            ref           = "refs/heads/develop", environment = "production"
          }
        }),
        jsonencode(var.static_promotion.application_promotion.delegations) == jsonencode({
          for alias, suffix in {
            observer       = "static-observer", normal = "static-normal",
            recovery       = "static-recovery",
            seeder         = "canary-seeder", verifier = "canary-verifier",
            fence_operator = "promotion-fence-operator", mode_seed = "mode-seed",
            mode_dispatch  = "mode-dispatch", mode_audit_launch = "mode-audit-launch",
            mode_observe   = "mode-observe",
          } : alias => "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-${suffix}"
        }),
        toset(keys(var.static_promotion.application_promotion.lease)) == toset(["bucket_arn",
        "key", "kms_key_arn"]) &&
        var.static_promotion.application_promotion.lease.key ==
        "shared/cnesdata-delivery/prod/coordination/cnesdata-prod.lease.json",
        toset(keys(var.static_promotion.application_promotion.evidence)) == toset([
        "bucket_arn", "prefix", "kms_key_arn"]) &&
        can(regex("^([A-Za-z0-9_-]+/)*lifecycle/$",
        var.static_promotion.application_promotion.evidence.prefix)),
        alltrue([for ref in [var.static_promotion.application_promotion.lease,
          var.static_promotion.application_promotion.evidence] :
          can(regex("^arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", ref.bucket_arn)) &&
          ref.bucket_arn != try(var.static_web.bucket_arn, "") &&
          can(regex("^arn:aws:kms:us-east-2:${var.account_id}:key/[A-Za-z0-9-]+$", ref.kms_key_arn))
        ]),
        alltrue([for value in [
          var.static_promotion.application_promotion.producer.source_closure_sha256,
          var.static_promotion.application_promotion.trust_sha256,
          var.static_promotion.application_promotion.policy_sha256] :
          value == tostring(value) && can(regex("^[0-9a-f]{64}$", value))
        ]),
        ]), false)), ((!contains(try(keys(var.static_promotion.application_promotion), []),
        "predecessor_reads") ?
        true : try(alltrue([
          toset(keys(var.static_promotion.application_promotion.predecessor_reads)) == toset([
            "protocol", "source_sha", "run_id", "run_attempt", "status", "purpose", "object_arns",
            "policy_sha256",
          ]),
          var.static_promotion.application_promotion.predecessor_reads.protocol == "lifecycle" ?
          (var.static_promotion.application_promotion.predecessor_reads.status ==
            "terminal" &&
            var.static_promotion.application_promotion.predecessor_reads.purpose ==
          "application") :
          (var.static_promotion.application_promotion.predecessor_reads.protocol ==
            "legacy-infra" &&
            contains(["planned", "applied"],
            var.static_promotion.application_promotion.predecessor_reads.status) &&
            contains(["acm-certificate", "bootstrap", "phase-a"],
          var.static_promotion.application_promotion.predecessor_reads.purpose)),
          var.static_promotion.application_promotion.predecessor_reads.source_sha == tostring(
          var.static_promotion.application_promotion.predecessor_reads.source_sha) &&
          can(regex("^[0-9a-f]{40}$",
          var.static_promotion.application_promotion.predecessor_reads.source_sha)),
          can(regex("^[0-9a-f]{64}$",
          var.static_promotion.application_promotion.predecessor_reads.policy_sha256)) &&
          var.static_promotion.application_promotion.predecessor_reads.policy_sha256 ==
          tostring(var.static_promotion.application_promotion.predecessor_reads.policy_sha256),
          alltrue([for key in ["run_id", "run_attempt"] :
            can(regex("^[1-9][0-9]*$", jsonencode(
            var.static_promotion.application_promotion.predecessor_reads[key])))
          ]),
          jsonencode(
          var.static_promotion.application_promotion.predecessor_reads.object_arns) ==
          jsonencode(sort([
            for name in concat(
              var.static_promotion.application_promotion.predecessor_reads.protocol == "lifecycle" ?
              ["terminal.json", "lease.json", "checkpoint.json"] :
              ["envelope.json", "lease.json", "checkpoint.json"],
              var.static_promotion.application_promotion.predecessor_reads.protocol ==
              "legacy-infra" &&
              var.static_promotion.application_promotion.predecessor_reads.status == "applied" ?
              ["drift.json"] : [],
              var.static_promotion.application_promotion.predecessor_reads.protocol ==
              "legacy-infra" &&
              var.static_promotion.application_promotion.predecessor_reads.status ==
              "applied" &&
              var.static_promotion.application_promotion.predecessor_reads.purpose ==
            "phase-a" ? ["ecr-before.json"] : []) :
            format("%s/%s%s/%s/%s/%s/%s",
              var.static_promotion.application_promotion.evidence.bucket_arn,
              var.static_promotion.application_promotion.predecessor_reads.protocol ==
              "lifecycle" ? var.static_promotion.application_promotion.evidence.prefix :
              trimsuffix(var.static_promotion.application_promotion.evidence.prefix, "lifecycle/"),
              var.static_promotion.application_promotion.predecessor_reads.source_sha,
              var.static_promotion.application_promotion.predecessor_reads.run_id,
              var.static_promotion.application_promotion.predecessor_reads.run_attempt,
            var.static_promotion.application_promotion.predecessor_reads.status, name)
          ])),
      ]), false))),
      toset(keys(var.static_promotion)) == toset([
        "mode", "application_promotion", "binding", "candidate_keys", "rollback_versions",
        "retire_versions", "multipart_keys", "inventory_sha256", "enabled_until",
      ]),
      contains(["observer-bootstrap", "operational"], var.static_promotion.mode),
      toset(keys(var.static_promotion.binding)) == toset([
        "release_id", "run_id", "run_attempt", "generation", "product_source_sha",
        "shared_source_sha",
        "static_plan_sha256",
      ]),
      var.static_promotion.binding.release_id == tostring(
      var.static_promotion.binding.release_id) &&
      can(regex("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$", var.static_promotion.binding.release_id)),
      alltrue([for key in ["run_id", "run_attempt", "generation"] :
        can(regex("^[1-9][0-9]*$", jsonencode(var.static_promotion.binding[key])))
      ]),
      alltrue([for key in ["product_source_sha", "shared_source_sha"] :
        var.static_promotion.binding[key] == tostring(var.static_promotion.binding[key]) &&
        can(regex("^[0-9a-f]{40}$", var.static_promotion.binding[key]))
      ]),
      toset(keys(var.static_web)) == toset(["bucket_arn", "distribution_arn"]) &&
      var.static_web.bucket_arn == "arn:aws:s3:::${var.name_prefix}-static-web" &&
      can(regex("^arn:aws:cloudfront::${var.account_id}:distribution/[A-Z0-9]+$",
      var.static_web.distribution_arn)),
      alltrue([for stamp in [var.static_promotion.enabled_until,
        var.static_promotion.application_promotion.enabled_until] :
        stamp == tostring(stamp) && can(regex("^[0-9-]{10}T[0-9:]{8}Z$", stamp)) &&
        can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", stamp))
      ]),
      timecmp(var.static_promotion.enabled_until,
      var.static_promotion.application_promotion.enabled_until) <= 0,
      alltrue([for field in ["candidate_keys", "multipart_keys"] :
        jsonencode(var.static_promotion[field]) == jsonencode(sort(distinct(
        var.static_promotion[field])))
      ]),
      alltrue([for key in concat(var.static_promotion.candidate_keys,
        var.static_promotion.multipart_keys,
        [for ref in concat(var.static_promotion.rollback_versions,
        var.static_promotion.retire_versions) : ref.key]) :
        key == tostring(key) && can(regex(
        "^(assets/[A-Za-z0-9._/-]+|index\\.html|theme-init\\.js)$", key)) &&
        alltrue([for segment in split("/", key) : segment != "" && !contains([".", ".."], segment)])
      ]),
      alltrue([for ref in concat(var.static_promotion.rollback_versions,
        var.static_promotion.retire_versions) :
        toset(keys(ref)) == toset(["key", "version_id"]) &&
        ref.version_id == tostring(ref.version_id) && ref.version_id != "null" &&
        can(regex("^[A-Za-z0-9._~+/=-]+$", ref.version_id))
      ]),
      alltrue([for field in ["rollback_versions", "retire_versions"] :
        length(var.static_promotion[field]) == length(distinct(var.static_promotion[field]))
      ]),
      length(var.static_promotion.rollback_versions) == 0 ||
      jsonencode([for ref in var.static_promotion.rollback_versions : ref.key]) ==
      jsonencode(["index.html", "theme-init.js"]),
      length(setintersection(toset(var.static_promotion.rollback_versions),
      toset(var.static_promotion.retire_versions))) == 0,
      try(var.static_promotion.mode == "operational", false) ? (
        can(regex("^[0-9a-f]{64}$", var.static_promotion.binding.static_plan_sha256)) &&
        var.static_promotion.binding.static_plan_sha256 == tostring(
        var.static_promotion.binding.static_plan_sha256) &&
        can(regex("^[0-9a-f]{64}$", var.static_promotion.inventory_sha256)) &&
        var.static_promotion.inventory_sha256 == tostring(var.static_promotion.inventory_sha256) &&
        length(var.static_promotion.candidate_keys) > 0
        ) : (var.static_promotion.binding.static_plan_sha256 == null &&
        var.static_promotion.inventory_sha256 == null && alltrue([
          for field in ["candidate_keys", "multipart_keys", "rollback_versions",
          "retire_versions"] :
          length(var.static_promotion[field]) == 0
      ])),
      alltrue([for policy in values(({
        observer = jsonencode({
          Version = "2012-10-17"
          Statement = [
            { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion",
              "s3:ListMultipartUploadParts"], Resource = [
              "${var.static_web.bucket_arn}/assets/*",
              "${var.static_web.bucket_arn}/index.html",
            "${var.static_web.bucket_arn}/theme-init.js"] },
            { Effect = "Allow", Action = ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
            Resource = var.static_web.bucket_arn },
            { Effect = "Allow", Action = "cloudfront:GetInvalidation",
            Resource = var.static_web.distribution_arn },
          ]
        })
        normal = jsonencode({
          Version = "2012-10-17"
          Statement = concat([
            { Effect = "Allow", Action = "s3:PutObject", Resource = try([
              for key in var.static_promotion.candidate_keys :
              "${var.static_web.bucket_arn}/${key}"], []),
              Condition = { DateLessThan = {
            "aws:CurrentTime" = var.static_promotion.enabled_until } } },
            { Effect = "Allow", Action = "s3:GetObject", Resource = try([
              for key in var.static_promotion.candidate_keys :
              "${var.static_web.bucket_arn}/${key}"], []),
              Condition = { DateLessThan = {
            "aws:CurrentTime" = var.static_promotion.enabled_until } } },
            { Effect = "Allow", Action = ["cloudfront:CreateInvalidation",
              "cloudfront:GetInvalidation"],
              Resource = var.static_web.distribution_arn, Condition = { DateLessThan = {
            "aws:CurrentTime" = var.static_promotion.enabled_until } } },
            ], try([for ref in var.static_promotion.retire_versions : {
              Effect   = "Allow", Action = "s3:DeleteObjectVersion"
              Resource = "${var.static_web.bucket_arn}/${ref.key}"
              Condition = merge({ DateLessThan = {
                "aws:CurrentTime" = var.static_promotion.enabled_until } }, { StringEquals = {
              "s3:VersionId" = ref.version_id } })
          }], []))
        })
        recovery = jsonencode({
          Version = "2012-10-17"
          Statement = concat([
            { Effect = "Allow", Action = ["cloudfront:CreateInvalidation",
              "cloudfront:GetInvalidation"],
              Resource = var.static_web.distribution_arn, Condition = { DateLessThan = {
            "aws:CurrentTime" = var.static_promotion.enabled_until } } },
            ], try(length(var.static_promotion.multipart_keys) > 0 ? [
              { Effect = "Allow", Action = ["s3:ListMultipartUploadParts",
                "s3:AbortMultipartUpload"],
                Resource = try([for key in var.static_promotion.multipart_keys :
                  "${var.static_web.bucket_arn}/${key}"], []), Condition = { DateLessThan = {
              "aws:CurrentTime" = var.static_promotion.enabled_until } } },
              ] : [], []), try(flatten([for ref in var.static_promotion.rollback_versions : [
                { Effect   = "Allow", Action = "s3:GetObjectVersion"
                  Resource = "${var.static_web.bucket_arn}/${ref.key}"
                  Condition = merge({ DateLessThan = {
                    "aws:CurrentTime" = var.static_promotion.enabled_until } }, { StringEquals = {
                "s3:VersionId" = ref.version_id } }) },
                { Effect   = "Allow", Action = "s3:PutObject"
                  Resource = "${var.static_web.bucket_arn}/${ref.key}"
                  Condition = merge({ DateLessThan = {
                    "aws:CurrentTime" = var.static_promotion.enabled_until } }, {
                    StringEquals = {
                      "s3:x-amz-copy-source" = format("%s/%s?versionId=%s",
                        trimprefix(var.static_web.bucket_arn, "arn:aws:s3:::"), ref.key,
                      urlencode(ref.version_id))
                    }
                    Bool = { "s3:ObjectCreationOperation" = "true" }
                  })
                },
          ]]), []))
        })
      })) : length(policy) <= 10240]),
      alltrue([for trust in values(({ for alias in keys(local.static_operations) :
        alias => jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect = "Allow", Action = "sts:AssumeRole"
            Principal = { AWS = try(
            var.static_promotion.application_promotion.application_role_arn, "") }
            Condition = alias == "observer" ? {
              StringLike = { "sts:RoleSessionName" = [
              "sp-i-${join("", [for n in range(40) : "?"])}"] }
              } : {
              StringEquals = { "sts:RoleSessionName" = ({ for alias,
                operations in local.static_operations : alias => sort([
                  for operation in operations : format("sp-%s-%s", operation == "inventory" ?
                    "i" : operation,
                    substr(sha256(
                      "${jsonencode(merge(var.static_promotion.binding, { operation = operation },
                  operation == "inventory" ? { static_plan_sha256 = null } : {}))}\n"), 0, 40))
              ]) })[alias] }
            }
          }]
      }) })) : length(trust) <= 2048]),
    ]), false)
    error_message = "static_promotion=invalid_contract"
  }
}

locals {
  static_enabled = var.static_promotion != null
  static_operational = local.static_enabled && try(var.static_promotion.mode ==
  "operational", false)
  static_shared       = try(var.static_promotion.application_promotion, {})
  static_binding      = try(var.static_promotion.binding, {})
  static_bucket       = try(var.static_web.bucket_arn, "")
  static_distribution = try(var.static_web.distribution_arn, "")
  static_candidates = try([
    for key in var.static_promotion.candidate_keys : "${local.static_bucket}/${key}"
  ], [])
  static_uploads = try([
    for key in var.static_promotion.multipart_keys : "${local.static_bucket}/${key}"
  ], [])
  static_expiry = {
    DateLessThan = { "aws:CurrentTime" = try(var.static_promotion.enabled_until,
    "1970-01-01T00:00:00Z") }
  }
  static_operations = {
    observer = ["inventory"], normal = ["publish", "retire"],
    recovery = ["rollback", "readback", "abort"],
  }
  static_sessions = { for alias, operations in local.static_operations : alias => sort([
    for operation in operations : format("sp-%s-%s", operation == "inventory" ? "i" : operation,
      substr(sha256("${jsonencode(merge(local.static_binding, { operation = operation },
    operation == "inventory" ? { static_plan_sha256 = null } : {}))}\n"), 0, 40))
  ]) }
  static_trusts = { for alias in keys(local.static_operations) : alias => jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRole"
      Principal = { AWS = try(local.static_shared.application_role_arn, "") }
      Condition = alias == "observer" ? {
        StringLike = { "sts:RoleSessionName" = ["sp-i-${join("", [for n in range(40) : "?"])}"] }
        } : {
        StringEquals = { "sts:RoleSessionName" = local.static_sessions[alias] }
      }
    }]
  }) }
  static_namespace = [
    "${local.static_bucket}/assets/*", "${local.static_bucket}/index.html",
    "${local.static_bucket}/theme-init.js",
  ]
  static_policies = {
    observer = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion",
        "s3:ListMultipartUploadParts"], Resource = local.static_namespace },
        { Effect = "Allow", Action = ["s3:ListBucketVersions", "s3:ListBucketMultipartUploads"],
        Resource = local.static_bucket },
        { Effect = "Allow", Action = "cloudfront:GetInvalidation",
        Resource = local.static_distribution },
      ]
    })
    normal = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        { Effect = "Allow", Action = "s3:PutObject", Resource = local.static_candidates,
        Condition = local.static_expiry },
        { Effect = "Allow", Action = "s3:GetObject", Resource = local.static_candidates,
        Condition = local.static_expiry },
        { Effect = "Allow", Action = ["cloudfront:CreateInvalidation",
          "cloudfront:GetInvalidation"],
        Resource = local.static_distribution, Condition = local.static_expiry },
        ], try([for ref in var.static_promotion.retire_versions : {
          Effect   = "Allow", Action = "s3:DeleteObjectVersion"
          Resource = "${local.static_bucket}/${ref.key}"
          Condition = merge(local.static_expiry, { StringEquals = {
          "s3:VersionId" = ref.version_id } })
      }], []))
    })
    recovery = jsonencode({
      Version = "2012-10-17"
      Statement = concat([
        { Effect = "Allow", Action = ["cloudfront:CreateInvalidation",
          "cloudfront:GetInvalidation"],
        Resource = local.static_distribution, Condition = local.static_expiry },
        ], length(local.static_uploads) > 0 ? [
        { Effect = "Allow", Action = ["s3:ListMultipartUploadParts", "s3:AbortMultipartUpload"],
        Resource = local.static_uploads, Condition = local.static_expiry },
        ] : [], try(flatten([for ref in var.static_promotion.rollback_versions : [
          { Effect   = "Allow", Action = "s3:GetObjectVersion"
            Resource = "${local.static_bucket}/${ref.key}"
            Condition = merge(local.static_expiry, { StringEquals = {
          "s3:VersionId" = ref.version_id } }) },
          { Effect   = "Allow", Action = "s3:PutObject"
            Resource = "${local.static_bucket}/${ref.key}"
            Condition = merge(local.static_expiry, {
              StringEquals = {
                "s3:x-amz-copy-source" = format("%s/%s?versionId=%s",
                  trimprefix(local.static_bucket, "arn:aws:s3:::"), ref.key, urlencode(
                ref.version_id))
              }
              Bool = { "s3:ObjectCreationOperation" = "true" }
            })
          },
      ]]), []))
    })
  }
}

resource "aws_iam_role" "static_observer" {
  count                = local.static_enabled ? 1 : 0
  name                 = "${var.name_prefix}-static-observer"
  assume_role_policy   = local.static_trusts.observer
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role" "static_normal" {
  count                = local.static_operational ? 1 : 0
  name                 = "${var.name_prefix}-static-normal"
  assume_role_policy   = local.static_trusts.normal
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role" "static_recovery" {
  count                = local.static_operational ? 1 : 0
  name                 = "${var.name_prefix}-static-recovery"
  assume_role_policy   = local.static_trusts.recovery
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "static_observer" {
  count  = local.static_enabled ? 1 : 0
  name   = "${var.name_prefix}-static-observer-runtime"
  role   = aws_iam_role.static_observer[0].name
  policy = local.static_policies.observer
}

resource "aws_iam_role_policy" "static_normal" {
  count  = local.static_operational ? 1 : 0
  name   = "${var.name_prefix}-static-normal-runtime"
  role   = aws_iam_role.static_normal[0].name
  policy = local.static_policies.normal
}

resource "aws_iam_role_policy" "static_recovery" {
  count  = local.static_operational ? 1 : 0
  name   = "${var.name_prefix}-static-recovery-runtime"
  role   = aws_iam_role.static_recovery[0].name
  policy = local.static_policies.recovery
}
