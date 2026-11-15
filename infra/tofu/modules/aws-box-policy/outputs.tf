output "policy_arn" {
  description = "The policy's ARN. The operator policy allows attaching exactly this one."
  value       = aws_iam_policy.session.arn
}

output "policy_arns" {
  description = "Every policy this module made, by purpose."
  value = {
    session        = aws_iam_policy.session.arn
    parameters     = aws_iam_policy.parameters.arn
    parameters_key = one(aws_iam_policy.parameters_key[*].arn)
    fleet_key      = one(aws_iam_policy.fleet_key[*].arn)
    session_logs   = one(aws_iam_policy.session_logs[*].arn)
  }
}
