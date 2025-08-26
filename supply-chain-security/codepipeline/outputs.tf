# Outputs for CodePipeline with security gates

output "pipeline_name" {
  description = "Name of the CodePipeline"
  value       = aws_codepipeline.secure_container_pipeline.name
}

output "pipeline_arn" {
  description = "ARN of the CodePipeline"
  value       = aws_codepipeline.secure_container_pipeline.arn
}

output "security_gates_project_name" {
  description = "Name of the security gates CodeBuild project"
  value       = aws_codebuild_project.security_gates.name
}

output "security_gates_project_arn" {
  description = "ARN of the security gates CodeBuild project"
  value       = aws_codebuild_project.security_gates.arn
}

output "image_build_project_name" {
  description = "Name of the image build CodeBuild project"
  value       = aws_codebuild_project.image_build.name
}

output "image_build_project_arn" {
  description = "ARN of the image build CodeBuild project"
  value       = aws_codebuild_project.image_build.arn
}

output "artifacts_bucket_name" {
  description = "Name of the S3 bucket for pipeline artifacts"
  value       = aws_s3_bucket.pipeline_artifacts.bucket
}

output "artifacts_bucket_arn" {
  description = "ARN of the S3 bucket for pipeline artifacts"
  value       = aws_s3_bucket.pipeline_artifacts.arn
}

output "pipeline_kms_key_id" {
  description = "ID of the KMS key used for pipeline encryption"
  value       = aws_kms_key.pipeline_key.key_id
}

output "pipeline_kms_key_arn" {
  description = "ARN of the KMS key used for pipeline encryption"
  value       = aws_kms_key.pipeline_key.arn
}

output "codepipeline_role_arn" {
  description = "ARN of the CodePipeline service role"
  value       = aws_iam_role.codepipeline_role.arn
}

output "codebuild_role_arn" {
  description = "ARN of the CodeBuild service role"
  value       = aws_iam_role.codebuild_role.arn
}

output "security_gates_log_group" {
  description = "CloudWatch log group for security gates"
  value       = aws_cloudwatch_log_group.security_gates_logs.name
}

output "image_build_log_group" {
  description = "CloudWatch log group for image build"
  value       = aws_cloudwatch_log_group.image_build_logs.name
}