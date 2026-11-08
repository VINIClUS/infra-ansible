variable "bucket_names" {
  description = "Exact names of the private data bucket and the Object Lock audit bucket."
  type = object({
    data  = string
    audit = string
  })
  nullable = false

  validation {
    condition = alltrue([
      for name in [var.bucket_names.data, var.bucket_names.audit] :
      can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", name))
    ])
    error_message = "bucket_names must be DNS-compatible S3 names without dots."
  }

  validation {
    condition     = var.bucket_names.data != var.bucket_names.audit
    error_message = "bucket_names.data and bucket_names.audit must be distinct."
  }
}
