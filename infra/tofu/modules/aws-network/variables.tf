variable "name" {
  type        = string
  default     = "ozbox"
  description = "Name for the network and its resources: lowercase letters, digits and single hyphens, starting with a letter, at most 30 characters."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$", var.name))
    error_message = "name must start with a lowercase letter, contain only lowercase letters, digits and hyphens, end with a letter or digit, and be at most 30 characters."
  }

  validation {
    condition     = !strcontains(var.name, "--")
    error_message = "name must not contain two hyphens in a row."
  }
}

variable "region" {
  type        = string
  description = "AWS region. The caller configures the provider with it; the module records it in a tag."
}

variable "vpc_cidr" {
  type        = string
  default     = "10.42.0.0/16"
  description = "A private IPv4 range for the VPC, a /16 inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16."

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && endswith(var.vpc_cidr, "/16")
    error_message = "vpc_cidr must be a valid IPv4 CIDR block ending in /16."
  }

  validation {
    condition     = can(regex("^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)", var.vpc_cidr))
    error_message = "vpc_cidr must be a private range (10.x, 172.16-31.x or 192.168.x)."
  }
}

variable "availability_zone" {
  type        = string
  default     = null
  description = "Availability zone for both subnets. null picks the first one available in the region."
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra tags. ozbox-managed, ozbox-network and ozbox-region are always set by the module and cannot be overridden."
}
