variable "table_name" {
  description = "Name of the single control-plane DynamoDB table."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{3,255}$", var.table_name))
    error_message = "table_name must use the DynamoDB table name shape."
  }
}
