# Container Image Security Scanning Integration

This module implements comprehensive container image security scanning using Amazon ECR and Inspector, with automated vulnerability threshold enforcement and build failure logic for critical vulnerabilities.

## Overview

The solution provides:

- **Automated Image Scanning**: ECR repositories configured with scan-on-push
- **Vulnerability Thresholds**: Configurable thresholds for critical, high, and medium vulnerabilities
- **Build Integration**: CodeBuild buildspec with scanning steps and failure logic
- **Immutable Tags**: ECR repositories configured with immutable tag settings
- **Lifecycle Management**: Automated cleanup of old images based on environment
- **Security Alerts**: SNS notifications for threshold violations
- **Compliance Reporting**: Detailed vulnerability reports and findings

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CodeBuild     │    │   Amazon ECR    │    │   Inspector     │
│                 │    │                 │    │                 │
│ • Build Image   │───▶│ • Store Image   │───▶│ • Scan Image    │
│ • Push to ECR   │    │ • Immutable     │    │ • Generate      │
│ • Wait for Scan │    │   Tags          │    │   Findings      │
│ • Check Results │    │ • Lifecycle     │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Build Success/  │    │   EventBridge   │    │     Lambda      │
│ Failure Based   │    │                 │    │                 │
│ on Thresholds   │    │ • Scan Events   │───▶│ • Process       │
│                 │    │ • Trigger       │    │   Results       │
│                 │    │   Lambda        │    │ • Send Alerts   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Components

### 1. CodeBuild Integration (`codebuild/buildspec.yml`)

- Automated Docker image building and pushing
- ECR authentication and repository management
- Inspector scan initiation and result polling
- Vulnerability threshold checking with build failure logic
- Configurable timeout and retry mechanisms

**Key Features:**
- Waits for scan completion (configurable timeout)
- Fails build if critical vulnerabilities exceed threshold
- Generates detailed vulnerability reports
- Supports parameter store configuration

### 2. ECR Repository Configuration (`terraform/ecr-repository.tf`)

- Immutable tag configuration for production images
- KMS encryption for images at rest
- Scan-on-push enabled for automatic vulnerability detection
- Repository policies for access control and image signing

**Security Features:**
- Immutable tags prevent tag overwriting
- KMS encryption with customer-managed keys
- Access policies with least-privilege principles
- SSL/TLS enforcement for all operations

### 3. Lifecycle Management (`ecr-policies/lifecycle-policy.json`)

- Automated cleanup of old images by environment
- Retention policies for production, staging, and development
- Untagged image cleanup to reduce storage costs
- Configurable retention periods

**Retention Rules:**
- Production images: Keep last 10 versions
- Staging images: Keep last 5 versions
- Development images: Keep for 7 days
- Untagged images: Delete after 1 day

### 4. Inspector Automation (`inspector-automation/scan-automation.sh`)

Standalone script for manual or CI/CD integration:
- Initiates ECR image scans
- Monitors scan progress with timeout handling
- Enforces vulnerability thresholds
- Generates detailed reports and findings

### 5. Event-Driven Processing (`lambda/process_scan_results.py`)

Lambda function triggered by ECR scan completion:
- Processes scan results automatically
- Sends SNS alerts for threshold violations
- Generates detailed vulnerability reports
- Integrates with monitoring and alerting systems

## Configuration

### Environment Variables

```bash
# Vulnerability Thresholds
CRITICAL_THRESHOLD=0      # Max critical vulnerabilities (default: 0)
HIGH_THRESHOLD=5          # Max high vulnerabilities (default: 5)
MEDIUM_THRESHOLD=20       # Max medium vulnerabilities (default: 20)

# AWS Configuration
AWS_REGION=us-east-1      # AWS region
AWS_ACCOUNT_ID=123456789012  # AWS account ID

# Repository Configuration
IMAGE_REPO_NAME=secure-app   # ECR repository name
IMAGE_TAG=latest            # Image tag
```

### Parameter Store Configuration

Store vulnerability thresholds in AWS Systems Manager Parameter Store:

```bash
aws ssm put-parameter \
  --name "/container-security/vulnerability-thresholds/critical" \
  --value "0" \
  --type "String"

aws ssm put-parameter \
  --name "/container-security/vulnerability-thresholds/high" \
  --value "5" \
  --type "String"
```

## Usage

### 1. Deploy Infrastructure

```bash
cd terraform
terraform init
terraform plan -var="repository_name=my-app" -var="environment=prod"
terraform apply
```

### 2. Configure CodeBuild Project

Use the provided `buildspec.yml` in your CodeBuild project:

```yaml
# In your CodeBuild project configuration
artifacts:
  files:
    - imagedefinitions.json
environment:
  compute-type: BUILD_GENERAL1_MEDIUM
  image: aws/codebuild/amazonlinux2-x86_64-standard:3.0
  type: LINUX_CONTAINER
  privileged-mode: true
source:
  buildspec: image-security-scanning/codebuild/buildspec.yml
```

### 3. Manual Scanning

Use the automation script for manual scans:

```bash
# Basic usage
./inspector-automation/scan-automation.sh my-app-repo latest

# With custom thresholds
CRITICAL_THRESHOLD=0 HIGH_THRESHOLD=3 \
./inspector-automation/scan-automation.sh my-app-repo v1.2.3
```

### 4. Monitor Results

- **CloudWatch Logs**: `/aws/ecr/{repository-name}/scan-results`
- **SNS Alerts**: Configured topic for threshold violations
- **ECR Console**: View detailed findings and recommendations

## Security Considerations

### Image Signing Requirements

For production environments, consider implementing image signing:

```bash
# Enable image signing in repository policy
{
  "Sid": "RequireImageSigning",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "ecr:PutImage",
  "Condition": {
    "StringNotEquals": {
      "ecr:image-signature": "true"
    }
  }
}
```

### Network Security

- ECR endpoints should use VPC endpoints for private access
- CodeBuild projects should run in private subnets
- Security groups should restrict access to necessary ports only

### Access Control

- Use IAM roles with least-privilege principles
- Implement resource-based policies for fine-grained access
- Enable CloudTrail logging for audit trails

## Troubleshooting

### Common Issues

1. **Scan Timeout**: Increase `SCAN_TIMEOUT` environment variable
2. **Permission Denied**: Verify IAM roles and policies
3. **Threshold Exceeded**: Review and update vulnerability thresholds
4. **Lambda Failures**: Check CloudWatch logs for detailed error messages

### Debugging Commands

```bash
# Check scan status
aws ecr describe-image-scan-findings \
  --repository-name my-app \
  --image-id imageTag=latest

# List repository images
aws ecr list-images --repository-name my-app

# View lifecycle policy
aws ecr get-lifecycle-policy --repository-name my-app
```

## Compliance and Reporting

### Vulnerability Reports

The system generates detailed reports including:
- Vulnerability counts by severity
- Detailed findings for critical/high vulnerabilities
- Remediation recommendations
- Compliance status against thresholds

### Metrics and KPIs

Track key security metrics:
- Mean Time to Remediation (MTTR) for vulnerabilities
- Percentage of images passing security scans
- Number of critical vulnerabilities detected
- Build failure rate due to security issues

### Integration with Security Tools

The solution integrates with:
- AWS Security Hub for centralized findings
- AWS Config for compliance monitoring
- Third-party SIEM systems via SNS/SQS
- Slack/Teams for real-time notifications

## Cost Optimization

- Lifecycle policies reduce storage costs
- Scan-on-push minimizes unnecessary scans
- Lambda functions use minimal compute resources
- CloudWatch log retention policies control log costs

## Next Steps

After implementing this module:
1. Configure SNS subscriptions for security team notifications
2. Integrate with existing CI/CD pipelines
3. Set up dashboards for vulnerability tracking
4. Implement automated remediation workflows
5. Configure integration with security incident response procedures