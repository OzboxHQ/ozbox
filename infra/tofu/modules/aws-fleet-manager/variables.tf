variable "regions" {
  type        = list(string)
  description = "The regions the fleet lives in. Every change statement is held to them (aws:RequestedRegion)."

  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", r))])
    error_message = "regions must be one or more AWS region names, like us-east-1."
  }
}

variable "machine_types" {
  type        = list(string)
  description = "The machine types a box's dashboard may launch or resize to (the catalog's mapping of the sizes it offers). Anything else is refused by IAM."

  validation {
    condition     = length(var.machine_types) > 0 && alltrue([for t in var.machine_types : can(regex("^[a-z0-9-]+\\.[a-z0-9]+$", t))])
    error_message = "machine_types must be one or more EC2 instance types, like m7i.xlarge."
  }
}

variable "image_ids" {
  type        = list(string)
  description = "Oz Box's own images: the only ones a box's dashboard may launch."

  validation {
    condition     = length(var.image_ids) > 0 && alltrue([for i in var.image_ids : can(regex("^ami-[0-9a-f]{8,17}$", i))])
    error_message = "image_ids must be one or more AMI ids."
  }
}

variable "max_volume_gb" {
  type        = number
  default     = 500
  description = "The largest volume a box's dashboard may create or grow to."

  validation {
    condition     = var.max_volume_gb >= 1 && var.max_volume_gb <= 16384
    error_message = "max_volume_gb must be between 1 and 16384."
  }
}

variable "max_iops" {
  type        = number
  default     = 6000
  description = "The most gp3 IOPS a volume may be given (3000 is gp3's baseline)."

  validation {
    condition     = var.max_iops >= 3000
    error_message = "max_iops must be at least gp3's baseline, 3000."
  }
}

variable "max_throughput" {
  type        = number
  default     = 500
  description = "The most gp3 throughput, in MB/s (125 is gp3's baseline)."

  validation {
    condition     = var.max_throughput >= 125
    error_message = "max_throughput must be at least gp3's baseline, 125."
  }
}

variable "window_permission_set" {
  type        = string
  description = "The name of the owner's Identity Center permission set for fleet windows. Only a sign-in with it may assume obx-fleet-change; main's role never can."

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,32}$", var.window_permission_set))
    error_message = "window_permission_set must be a permission set name (letters, digits, _ and -)."
  }
}

variable "read_costs" {
  type        = bool
  default     = false
  description = "Let the read role read the bill. Turn on only in an account that holds nothing but Oz Box and is a member account (Cost Explorer cannot be limited by tag, so the account is the boundary)."
}
