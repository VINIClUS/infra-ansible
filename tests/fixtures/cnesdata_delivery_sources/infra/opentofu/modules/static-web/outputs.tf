output "bucket_name" {
  value = aws_s3_bucket.this.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}

output "distribution_id" {
  value = aws_cloudfront_distribution.this.id
}

output "distribution_arn" {
  value = aws_cloudfront_distribution.this.arn
}

output "distribution_domain_name" {
  value = aws_cloudfront_distribution.this.domain_name
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.this.arn
}

output "api_base_url" {
  value = "https://api.cnesdata.com.br/api/v1"
}

output "free_subscription_binding_input" {
  value = {
    distribution_arn = aws_cloudfront_distribution.this.arn,
    web_acl_arn      = aws_wafv2_web_acl.this.arn
  }
}
