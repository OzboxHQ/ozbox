output "read_role_arn" {
  value       = aws_iam_role.read.arn
  description = "obx-fleet-read: main's credential holder assumes it for the fleet inventory."
}

output "change_role_arn" {
  value       = aws_iam_role.change.arn
  description = "obx-fleet-change: assumed only from the owner's computer, one plan at a time."
}
