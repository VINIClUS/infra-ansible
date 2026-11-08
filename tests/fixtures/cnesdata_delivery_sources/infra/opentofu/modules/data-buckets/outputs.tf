output "data_bucket_name" {
  description = "Data bucket name for AWS_DATA_BUCKET."
  value       = aws_s3_bucket.data.bucket
}

output "data_bucket_arn" {
  description = <<-EOT
    Data bucket ARN, the only bucket-level IAM target. Runtime s3:ListBucket on it is a documented
    exception (the stat path tells 403 from 404); PROD-INFRA-008 narrows it by s3:prefix.
  EOT
  value       = aws_s3_bucket.data.arn
}

output "data_prefix_arns" {
  description = "Exact object ARN pattern of each canonical data prefix, keyed by prefix."
  value = {
    for prefix in local.data_prefixes : prefix => "${aws_s3_bucket.data.arn}/${prefix}/*"
  }
}

output "serving_origin" {
  description = "HTTPS origin of signed serving downloads, for the dashboard CSP connect-src."
  value       = "https://${aws_s3_bucket.data.bucket_regional_domain_name}"
}

output "audit_bucket_name" {
  description = "Audit bucket name for AWS_AUDIT_BUCKET."
  value       = aws_s3_bucket.audit.bucket
}

output "audit_bucket_arn" {
  description = "Audit bucket ARN for s3:GetBucketObjectLockConfiguration."
  value       = aws_s3_bucket.audit.arn
}

output "audit_prefix_arn" {
  description = "Exact object ARN pattern of the audit prefix written by the Object Lock sink."
  value       = "${aws_s3_bucket.audit.arn}/${local.audit_prefix}/*"
}

output "audit_retention_days" {
  description = "Default COMPLIANCE retention in days; AWS_AUDIT_RETENTION_DAYS must match it."
  value       = local.audit_default_retention.days
}
