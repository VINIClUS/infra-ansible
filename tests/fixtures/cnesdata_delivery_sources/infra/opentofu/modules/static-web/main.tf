terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.33"
      configuration_aliases = [aws.global_edge]
    }
  }
}

locals {
  public_domain        = "cnesdata.com.br"
  api_origin           = "https://api.cnesdata.com.br"
  rollback_window_days = 7
  hosted_login_origin  = trimsuffix(var.cognito.hosted_login_origin, "/")
  serving_origin       = trimsuffix(var.serving_origin, "/")
  csp = join("", [
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; ",
    "img-src 'self'; connect-src 'self' ",
    "${local.hosted_login_origin} ${local.api_origin} ${local.serving_origin}; ",
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  ])
  caching_optimized_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  csp_header = (
    var.csp_mode == "enforce" ? "content-security-policy" : "content-security-policy-report-only"
  )
  response_headers = merge(
    {
      "x-content-type-options" = "nosniff"
      "x-frame-options"        = "DENY"
      "referrer-policy"        = "strict-origin-when-cross-origin"
      "permissions-policy"     = "camera=(), microphone=(), geolocation=()"
      (local.csp_header)       = local.csp
    },
    var.certificate_domain_validated ? { "strict-transport-security" = "max-age=31536000" } : {},
  )
}

resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFront"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.this.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.this.arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket     = aws_s3_bucket.this.id
  depends_on = [aws_s3_bucket_versioning.this]

  rule {
    id     = "static-web-gc"
    status = "Enabled"

    filter {
      tag {
        key   = "static-web-gc"
        value = "eligible"
      }
    }

    noncurrent_version_expiration {
      noncurrent_days           = local.rollback_window_days
      newer_noncurrent_versions = 1
    }
  }

  rule {
    id     = "static-web-abort-multipart"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_cloudfront_origin_access_control" "this" {
  name                              = "cnesdata-prod-static-web"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "spa" {
  name    = "cnesdata-prod-static-web"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = file("${path.module}/function.js")
}

resource "aws_cloudfront_function" "headers" {
  name    = "cnesdata-prod-static-web-headers"
  runtime = "cloudfront-js-2.0"
  publish = true
  code = templatefile("${path.module}/headers.js", {
    headers = jsonencode(local.response_headers)
  })
}

resource "aws_wafv2_web_acl" "this" {
  provider = aws.global_edge
  name     = "cnesdata-prod-static-web"
  scope    = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 0
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "AWSManagedRulesCommonRuleSet"
    }
  }

  rule {
    name     = "AWS-AWSManagedRulesAmazonIpReputationList"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      sampled_requests_enabled   = false
      cloudwatch_metrics_enabled = false
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
    }
  }

  visibility_config {
    sampled_requests_enabled   = false
    cloudwatch_metrics_enabled = false
    metric_name                = "cnesdata-prod-static-web"
  }
}

resource "aws_cloudfront_distribution" "this" {
  enabled    = true
  aliases    = [local.public_domain]
  web_acl_id = aws_wafv2_web_acl.this.arn

  origin {
    origin_id                = "static-web-s3"
    domain_name              = aws_s3_bucket.this.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.this.id
  }

  default_cache_behavior {
    target_origin_id       = "static-web-s3"
    cache_policy_id        = local.caching_optimized_policy_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa.arn
    }

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.headers.arn
    }
  }

  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  custom_error_response {
    error_code            = 403
    error_caching_min_ttl = 0
  }

  custom_error_response {
    error_code            = 404
    error_caching_min_ttl = 0
  }
}
