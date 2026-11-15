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
