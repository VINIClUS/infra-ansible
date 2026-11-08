terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

locals {
  table_key = {
    hash_key  = "pk"
    range_key = "sk"
  }
  key_attribute_type = "S"
  global_secondary_indexes = {
    gsi1 = { hash_key = "gsi1pk", range_key = "gsi1sk", projection_type = "ALL" }
    gsi2 = { hash_key = "gsi2pk", range_key = "gsi2sk", projection_type = "ALL" }
    gsi3 = { hash_key = "gsi3pk", range_key = "gsi3sk", projection_type = "ALL" }
    gsi4 = { hash_key = "gsi4pk", range_key = "gsi4sk", projection_type = "ALL" }
    gsi5 = { hash_key = "gsi5pk", range_key = "gsi5sk", projection_type = "ALL" }
    gsi6 = { hash_key = "gsi6pk", range_key = "gsi6sk", projection_type = "ALL" }
  }
  key_attributes = toset(concat(
    values(local.table_key),
    flatten([
      for index in values(local.global_secondary_indexes) : [index.hash_key, index.range_key]
    ]),
  ))
  ttl_attribute = "expires_at"
  on_demand_throughput = {
    max_read_request_units  = 100
    max_write_request_units = 25
  }
  point_in_time_recovery_days = 35
}

# Encryption at rest uses the AWS-owned key (no server_side_encryption block): no KMS request
# charges and no key-policy coupling with the shared KMS key (deployment spec section 9).
resource "aws_dynamodb_table" "control_plane" {
  name                        = var.table_name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = local.table_key.hash_key
  range_key                   = local.table_key.range_key
  deletion_protection_enabled = true

  dynamic "attribute" {
    for_each = local.key_attributes
    content {
      name = attribute.value
      type = local.key_attribute_type
    }
  }

  dynamic "global_secondary_index" {
    for_each = local.global_secondary_indexes
    content {
      name            = global_secondary_index.key
      projection_type = global_secondary_index.value.projection_type

      key_schema {
        attribute_name = global_secondary_index.value.hash_key
        key_type       = "HASH"
      }

      key_schema {
        attribute_name = global_secondary_index.value.range_key
        key_type       = "RANGE"
      }

      on_demand_throughput {
        max_read_request_units  = local.on_demand_throughput.max_read_request_units
        max_write_request_units = local.on_demand_throughput.max_write_request_units
      }
    }
  }

  on_demand_throughput {
    max_read_request_units  = local.on_demand_throughput.max_read_request_units
    max_write_request_units = local.on_demand_throughput.max_write_request_units
  }

  point_in_time_recovery {
    enabled                 = true
    recovery_period_in_days = local.point_in_time_recovery_days
  }

  ttl {
    attribute_name = local.ttl_attribute
    enabled        = true
  }

  lifecycle {
    prevent_destroy = true
  }
}
