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
}

variable "backend" {
  type = object({
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
  nullable = false
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

variable "kms_key_arn" {
  type     = string
  nullable = false

  validation {
    condition = can(regex(join("", [
      "^arn:aws:kms:us-east-2:836651842853:key/",
      "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$",
    ]), var.kms_key_arn))
    error_message = "kms_key_arn deve ser ARN de chave KMS da conta 836651842853 em us-east-2."
  }
}
