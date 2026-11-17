output "machine_id" {
  description = "EC2 instance id."
  value       = aws_instance.box.id
}

output "work_volume_id" {
  description = "The persistent /work EBS volume id."
  value       = aws_ebs_volume.work.id
}

output "machine_type" {
  description = "The instance type actually used."
  value       = aws_instance.box.instance_type
}

output "cloud_init" {
  description = "The first-boot configuration, uncompressed. The machine receives it gzip-compressed; this is for review and tests. It holds no secret."
  value       = local.cloud_init
}

output "notify_grants" {
  description = "What the box's role may do to send alerts (B4-9): the SES identity it may send from and the SNS topic it may publish to. null when notify_send_grants is off."
  value = var.notify_send_grants ? {
    ses_send_email = var.notify_ses_identity_arn
    sns_publish    = var.notify_sns_topic_arn
  } : null
}
