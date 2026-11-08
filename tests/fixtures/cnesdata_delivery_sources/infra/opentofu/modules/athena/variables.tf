variable "name_prefix" {
  description = "Product namespace for the workgroup, bucket, topic, alarm and Lambda names."
  type        = string
  nullable    = false
}

variable "account_id" {
  description = "Production account ID bound into ARNs, trust and topic policies."
  type        = string
  nullable    = false
}

variable "budget_arn" {
  description = "Shared Budget ARN allowed to publish to the cutoff topic as the freeze hook."
  type        = string
  nullable    = false
}
