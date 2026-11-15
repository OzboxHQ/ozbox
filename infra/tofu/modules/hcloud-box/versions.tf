terraform {
  required_version = ">= 1.7.0"

  # Empty on purpose: Oz Box gives it the state directory (-backend-config); run by hand it is the default local backend.
  backend "local" {}

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = ">= 1.48.0, < 2.0.0"
    }
  }
}
