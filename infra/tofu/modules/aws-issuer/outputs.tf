output "function_url" {
  description = "The issuer's address (AWS_IAM only): what the CLI and the box's secrets service call, signed with their own AWS credentials."
  value       = aws_lambda_function_url.issuer.function_url
}

output "function_arn" {
  description = "The issuer function."
  value       = aws_lambda_function.issuer.arn
}

output "issuer_role_arn" {
  description = "The issuer's own role: it can assume the release role and cannot read a secret."
  value       = aws_iam_role.issuer.arn
}

output "release_role_arn" {
  description = "The one role that can read Production, assumable only by the issuer."
  value       = aws_iam_role.release.arn
}

output "production_key_arn" {
  description = "The Production KMS key. Encrypt new Production secrets with it (the operator roles may); only the release role decrypts."
  value       = aws_kms_key.production.arn
}

output "invoke_policy_arn" {
  description = "Attach to a box's instance role so it can ask the issuer. It reads nothing."
  value       = aws_iam_policy.invoke.arn
}

output "config_parameter" {
  description = "Where the issuer's pinned public keys are kept (a String parameter, no secret)."
  value       = aws_ssm_parameter.config.name
}

output "secret_name_prefix" {
  description = "Production secrets are named under this prefix."
  value       = var.secret_name_prefix
}
