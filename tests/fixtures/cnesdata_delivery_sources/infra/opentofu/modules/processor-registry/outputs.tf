output "repository_name" {
  description = "Private processor repository name."
  value       = aws_ecr_repository.this.name
}

output "repository_arn" {
  description = "Private processor repository ARN."
  value       = aws_ecr_repository.this.arn
}

output "repository_uri" {
  description = "Private processor repository URI."
  value       = aws_ecr_repository.this.repository_url
}
