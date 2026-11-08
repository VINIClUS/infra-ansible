locals {
  name_prefix = "cnesdata-prod"
  common_tags = {
    Project     = "cnesdata"
    Environment = "prod"
    ManagedBy   = "opentofu"
    Owner       = "vinisantana"
  }
}

provider "aws" {
  region = "us-east-2"

  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias  = "global_edge"
  region = "us-east-1"

  default_tags {
    tags = local.common_tags
  }
}
