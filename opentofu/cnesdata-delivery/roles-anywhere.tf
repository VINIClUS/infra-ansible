resource "aws_rolesanywhere_trust_anchor" "ca" {
  name    = var.identity.trust_anchor_name
  enabled = true
  source {
    source_type = "CERTIFICATE_BUNDLE"
    source_data {
      x509_certificate_data = var.ca_certificate_pem
    }
  }
  lifecycle {
    prevent_destroy = true
    precondition {
      condition = (
        data.aws_caller_identity.current.account_id == var.account_id && (
          var.local_controller_root_apply
          ? data.aws_caller_identity.current.arn == "arn:aws:iam::${var.account_id}:root"
          : can(regex("^arn:aws:sts::${var.account_id}:assumed-role/[A-Za-z0-9_+=,.@/-]+/[A-Za-z0-9_+=,.@-]+$", data.aws_caller_identity.current.arn))
        )
      )
      error_message = "Delivery requires an approved temporary assumed-role session in the expected account; IAM user credentials are forbidden, and root is accepted only with local_controller_root_apply=true, which refuses every session."
    }
  }
}

resource "aws_iam_role" "api" {
  name                 = var.identity.role_name
  max_session_duration = 3600
  # Product permissions are attached by CnesData runtime-iam, not this root.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "rolesanywhere.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_rolesanywhere_trust_anchor.ca.arn }
        StringEquals = {
          "aws:SourceAccount"               = var.account_id
          "aws:PrincipalTag/x509Subject/CN" = var.identity.common_name
          "aws:PrincipalTag/x509SAN/URI"    = var.identity.san_uri
        }
        DateLessThan = {
          "aws:CurrentTime" = var.activation_enabled ? try(var.crl_handoff.next_update, "1970-01-01T00:00:00Z") : "1970-01-01T00:00:00Z"
        }
      }
    }]
  })
  lifecycle {
    prevent_destroy = true
    precondition {
      condition = !var.activation_enabled || try(
        var.crl_handoff != null && var.crl_handoff.enabled &&
        var.crl_handoff.trust_anchor_arn == aws_rolesanywhere_trust_anchor.ca.arn &&
        var.crl_handoff.ca_pem_sha256 == sha256(var.ca_certificate_pem) &&
        var.crl_handoff_sha256 == sha256(jsonencode(var.crl_handoff)) &&
        timecmp(var.crl_handoff.this_update, plantimestamp()) <= 0 &&
        timecmp(var.crl_handoff.next_update, plantimestamp()) > 0,
        false
      )
      error_message = "Activation requires an unexpired, exact-anchor/CA-bound canonical CRL handoff and controller-verified live provenance."
    }
  }
}

resource "aws_rolesanywhere_profile" "api" {
  name                     = var.identity.profile_name
  enabled                  = var.activation_enabled
  role_arns                = [aws_iam_role.api.arn]
  duration_seconds         = var.identity.duration_seconds
  accept_role_session_name = false
  # Provider 6.54.0 uses the service's default CN / first SAN URI mappings.
  # Readback and single-application-URI issuance are mandatory operational gates.
  lifecycle {
    prevent_destroy = true
  }
}
