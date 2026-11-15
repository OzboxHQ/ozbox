terraform {
  required_version = ">= 1.7.0"

  # Empty on purpose: Oz Box gives it the state directory (-backend-config); run by hand it is the default local backend.
  backend "local" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0, < 7.0.0"
    }
  }
}
