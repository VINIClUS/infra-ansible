terraform {
  backend "s3" {
    key          = "shared/cnesdata-delivery/prod/opentofu.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
