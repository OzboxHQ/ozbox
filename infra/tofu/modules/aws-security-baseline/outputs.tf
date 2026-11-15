output "session_log_bucket" {
  description = "The locked session-log bucket (the aws-box module's session_log_bucket), or null when session logs are off."
  value       = var.enable_session_logs ? aws_s3_bucket.session_logs[0].id : null
}

output "patch_group" {
  description = "The patch group (the aws-box module's patch_group), or null when patching is off."
  value       = var.enable_patching ? var.patch_group : null
}

output "guardduty_detector_id" {
  description = "The GuardDuty detector Runtime Monitoring is on, or null when it is off."
  value       = var.enable_guardduty_runtime ? local.detector_id : null
}
