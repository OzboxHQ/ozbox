output "adopt_document_name" {
  description = "The SSM document `ozbox adopt-fleet-key` sends to a box (a fixed set of ozbox programs, chosen by an enum). The CLI derives the same name from the fleet name."
  value       = aws_ssm_document.adopt.name
}

output "operator_adopt_policy_json" {
  description = "The IAM policy to attach to whoever runs `ozbox adopt-fleet-key`: SendCommand on the adopt document only, to boxes tagged ozbox-managed=true, plus reading a command's result (not stopping one). It never allows AWS-RunShellScript."
  value       = data.aws_iam_policy_document.operator_adopt.json
}

output "adopt_document_sha256" {
  description = "The SHA-256 of the adopt document's text. The ozbox program carries the same text and sends this hash with every command; whether Systems Manager refuses a command whose pinned hash differs from the document's is unproven (real-box check 1)."
  value       = sha256(file("${path.module}/adopt-document.yaml"))
}
