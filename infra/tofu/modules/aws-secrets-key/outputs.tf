output "key_arn" {
  description = "The key's ARN: pass it to the box module as secrets_key_arn."
  value       = aws_kms_key.secrets.arn
}

output "key_id" {
  description = "The key id, for OZBOX_KMS_KEY_ID on a box."
  value       = aws_kms_key.secrets.key_id
}

output "fleet" {
  description = "The fleet tag value a box's role must carry (the box module sets it)."
  value       = var.name
}
