output "config_recorder_name" {
  description = "Name of the Config configuration recorder"
  value       = aws_config_configuration_recorder.container_security.name
}

output "config_delivery_channel_name" {
  description = "Name of the Config delivery channel"
  value       = aws_config_delivery_channel.container_security.name
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for Config"
  value       = aws_s3_bucket.config_bucket.bucket
}

output "config_rules" {
  description = "List of Config rule names"
  value = [
    aws_config_config_rule.eks_endpoint_access.name,
    aws_config_config_rule.eks_logging_enabled.name,
    aws_config_config_rule.ecr_scan_on_push.name,
    aws_config_config_rule.ecr_lifecycle_policy.name,
    aws_config_config_rule.iam_root_access_key.name,
    aws_config_config_rule.s3_bucket_public_access.name,
    aws_config_config_rule.cloudtrail_enabled.name,
    aws_config_config_rule.guardduty_enabled.name,
    aws_config_config_rule.kms_key_rotation.name,
    aws_config_config_rule.eks_security_groups.name
  ]
}

output "config_alerts_topic_arn" {
  description = "ARN of the SNS topic for Config alerts"
  value       = aws_sns_topic.config_alerts.arn
}