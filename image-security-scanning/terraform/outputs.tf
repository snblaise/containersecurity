output "repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.secure_app_repo.repository_url
}

output "repository_arn" {
  description = "ARN of the ECR repository"
  value       = aws_ecr_repository.secure_app_repo.arn
}

output "repository_name" {
  description = "Name of the ECR repository"
  value       = aws_ecr_repository.secure_app_repo.name
}

output "kms_key_id" {
  description = "KMS key ID used for ECR encryption"
  value       = aws_kms_key.ecr_key.key_id
}

output "kms_key_arn" {
  description = "KMS key ARN used for ECR encryption"
  value       = aws_kms_key.ecr_key.arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function processing scan results"
  value       = aws_lambda_function.process_scan_results.function_name
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for ECR scan results"
  value       = aws_cloudwatch_log_group.ecr_scan_logs.name
}

output "scan_automation_script" {
  description = "Path to the scan automation script"
  value       = "../inspector-automation/scan-automation.sh"
}

output "buildspec_file" {
  description = "Path to the CodeBuild buildspec file"
  value       = "../codebuild/buildspec.yml"
}