variable "account_id" {
  type        = string
  description = "The 12-digit AWS account id (used in the session-log bucket name and policies)."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  type        = string
  description = "The region these services are turned on in. GuardDuty, the session-log bucket and Patch Manager are all per region."
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra tags. ozbox-managed is always set and cannot be overridden."
}

# ---- GuardDuty Runtime Monitoring ----

variable "enable_guardduty_runtime" {
  type        = bool
  default     = false
  description = "Turn on GuardDuty Runtime Monitoring for EC2 in this region, with the agent installed and kept by GuardDuty through Systems Manager. Off by default: it bills per vCPU of monitored instances, plus a VPC endpoint in each monitored VPC."
}

variable "existing_guardduty_detector_id" {
  type        = string
  default     = null
  description = "A GuardDuty detector this region already has (there is at most one per region). The module then only turns the feature on and never creates or deletes the detector. null: the module creates one."
}

# ---- Session logs ----

variable "enable_session_logs" {
  type        = bool
  default     = false
  description = "Create the locked session-log bucket and tell Session Manager to write shell session logs to it."
}

variable "session_log_retention_days" {
  type        = number
  default     = 365
  description = "How long a log object is locked. Objects cannot be changed or deleted before this, and are expired a little after."

  validation {
    condition     = var.session_log_retention_days >= 1 && var.session_log_retention_days <= 3650 && floor(var.session_log_retention_days) == var.session_log_retention_days
    error_message = "session_log_retention_days must be a whole number from 1 to 3650."
  }
}

variable "session_log_retention_mode" {
  type        = string
  default     = "GOVERNANCE"
  description = "GOVERNANCE: a person with the bypass permission (which nothing here grants) can remove a log early. COMPLIANCE: nobody can, not even the account root, until the retention ends, and the bucket cannot be deleted before then. COMPLIANCE cannot be undone: choose it deliberately."

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.session_log_retention_mode)
    error_message = "session_log_retention_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "manage_session_preferences" {
  type        = bool
  default     = true
  description = "Write the account's Session Manager preferences document (SSM-SessionManagerRunShell) so it logs to the bucket. That document is one per account and region: if it exists, `ozbox harden` sets this false and says how to point it at the bucket by hand (or import it yourself first)."
}

# ---- Patch Manager ----

variable "enable_patching" {
  type        = bool
  default     = false
  description = "Create an Ubuntu patch baseline, a patch group and a weekly maintenance window that installs patches and never restarts a box."
}

variable "patch_group" {
  type        = string
  default     = "ozbox"
  description = "The patch group boxes join through the Patch Group tag (the aws-box module's patch_group)."
}

variable "patch_schedule" {
  type        = string
  default     = "cron(0 3 ? * SUN *)"
  description = "When the maintenance window opens (an AWS cron or rate expression)."
}

variable "patch_schedule_timezone" {
  type        = string
  default     = "UTC"
  description = "The time zone the schedule is read in."
}

variable "patch_approve_after_days" {
  type        = number
  default     = 7
  description = "A patch is approved this many days after it is released."

  validation {
    condition     = var.patch_approve_after_days >= 0 && var.patch_approve_after_days <= 100
    error_message = "patch_approve_after_days must be 0 to 100."
  }
}
