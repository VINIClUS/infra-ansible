variable "account_id" {
  type     = string
  nullable = false

  validation {
    condition     = var.account_id == "836651842853"
    error_message = "account_id deve ser 836651842853."
  }
}

variable "region" {
  type     = string
  nullable = false

  validation {
    condition     = var.region == "us-east-2"
    error_message = "region deve ser us-east-2."
  }
}

variable "tags" {
  type     = map(string)
  nullable = false
}

variable "roots" {
  type = object({
    foundation = object({
      owner = string
      backend = object({
        bucket = string
        key    = string
      })
      logging = object({
        bucket = string
        prefix = string
      })
    })
    budget-backend = object({
      owner = string
      backend = object({
        bucket = string
        key    = string
      })
      logging = object({
        bucket = string
        prefix = string
      })
    })
  })
  nullable = false

  validation {
    condition = alltrue([
      for root in values(var.roots) : root.backend.bucket != root.logging.bucket &&
      root.logging.prefix == "access/${root.backend.bucket}/"
    ])
    error_message = "source and sink buckets must differ; prefix must be access/<source-bucket>/."
  }
}

variable "identities" {
  type = object({
    operator = object({
      name = string
      path = string
    })
    readback = object({
      name = string
      path = string
    })
    executor = object({
      name = string
      path = string
    })
    boundary = object({
      name = string
      path = string
    })
  })
  nullable = false
}
