# Container Security Monitoring and Compliance

This directory contains comprehensive monitoring and compliance configurations for AWS container security, implementing CloudWatch logging, GuardDuty threat detection, and CloudTrail audit logging for EKS clusters.

## Components

### CloudWatch Integration (`cloudwatch/`)
- **Log Groups**: Centralized logging for EKS control plane, application logs, security events, and audit trails
- **Alarms**: Real-time alerting for security policy violations, image pull failures, and privileged container starts
- **Metrics**: Custom metrics for Pod Security Admission violations and network policy enforcement

### GuardDuty Integration (`guardduty/`)
- **EKS Protection**: Threat detection for Kubernetes audit logs and runtime monitoring
- **Malware Protection**: EC2 instance scanning with EBS volume analysis
- **Threat Intelligence**: Custom threat intelligence feeds for container-specific threats
- **Event Integration**: EventBridge rules for high-severity findings with SNS alerting

### CloudTrail Logging (`cloudtrail/`)
- **API Audit Trails**: Comprehensive logging of EKS, ECR, and Secrets Manager API calls
- **Advanced Event Selectors**: Focused monitoring on container-related AWS services
- **Log Retention**: Configurable retention policies for compliance requirements
- **Encryption**: KMS encryption for all audit logs in transit and at rest

## Security Features

### Real-time Monitoring
- Pod Security Admission policy violations
- Network policy enforcement failures
- Privileged container deployment attempts
- Image pull failures and security events
- GuardDuty threat detection findings

### Compliance Logging
- EKS control plane API calls
- Container registry access and modifications
- Secrets Manager operations
- KMS key usage for encryption operations
- Multi-region trail coverage for global visibility

### Threat Detection
- Container runtime anomaly detection
- Cryptocurrency mining detection
- Command and control communication
- Privilege escalation attempts
- Container escape detection

## Configuration

### Prerequisites
- EKS cluster with audit logging enabled
- KMS key for encryption
- SNS topics for alerting (optional)
- S3 bucket permissions for CloudTrail

### Terraform Variables
```hcl
cluster_name = "production-eks"
kms_key_arn  = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

common_tags = {
  Environment = "production"
  Project     = "container-security"
  Owner       = "security-team"
}

# Log retention settings
log_retention_days         = 30
security_log_retention_days = 90
audit_log_retention_days   = 365
```

### Deployment
```bash
# Deploy CloudWatch logging
cd cloudwatch/
terraform init
terraform plan -var-file="../terraform.tfvars"
terraform apply

# Deploy GuardDuty integration
cd ../guardduty/
terraform init
terraform plan -var-file="../terraform.tfvars"
terraform apply

# Deploy CloudTrail logging
cd ../cloudtrail/
terraform init
terraform plan -var-file="../terraform.tfvars"
terraform apply
```

## Monitoring Dashboards

### Security Events Dashboard
- Pod Security Admission violations over time
- Network policy denial rates
- Image security scan results
- GuardDuty findings by severity

### Compliance Dashboard
- API call volume by service
- Failed authentication attempts
- Privilege escalation events
- Audit log completeness metrics

## Alerting Configuration

### Critical Alerts (Immediate Response)
- Privileged container starts
- Pod Security Admission violations
- GuardDuty HIGH/CRITICAL findings
- Failed image signature verification

### Warning Alerts (Investigation Required)
- Network policy violations above threshold
- Image pull failures
- Unusual API call patterns
- Secrets access anomalies

## Integration with SIEM

### Log Forwarding
CloudWatch logs can be forwarded to external SIEM systems using:
- Kinesis Data Firehose for real-time streaming
- Lambda functions for custom log processing
- CloudWatch Logs Subscription Filters

### Log Format
All security events are logged in structured JSON format with standardized fields:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "cluster_name": "production-eks",
  "event_type": "security_violation",
  "severity": "HIGH",
  "source": "pod_security_admission",
  "details": {
    "namespace": "default",
    "pod_name": "suspicious-pod",
    "violation": "privileged_container",
    "user": "system:serviceaccount:default:deployer"
  }
}
```

## Troubleshooting

### Common Issues

**CloudWatch Logs Not Appearing**
- Verify EKS cluster has audit logging enabled
- Check IAM permissions for log group access
- Confirm KMS key permissions for encryption

**GuardDuty Findings Not Generated**
- Ensure EKS audit logs are enabled in cluster configuration
- Verify GuardDuty detector is active in the region
- Check EventBridge rule configuration for finding routing

**CloudTrail Logs Missing**
- Confirm S3 bucket policy allows CloudTrail access
- Verify CloudTrail is enabled and logging
- Check advanced event selectors configuration

### Log Analysis Queries

**Find Pod Security Violations**
```
fields @timestamp, cluster_name, namespace, pod_name, violation
| filter event_type = "pod_security_violation"
| sort @timestamp desc
| limit 100
```

**Analyze Image Pull Failures**
```
fields @timestamp, image, error_message, namespace
| filter event_type = "image_pull_failure"
| stats count() by image
| sort count desc
```

## Cost Optimization

### Log Retention Strategy
- Standard logs: 30 days in CloudWatch, lifecycle to S3
- Security logs: 90 days for investigation
- Audit logs: 7 years for compliance (S3 Deep Archive)

### GuardDuty Cost Management
- Use finding frequency settings to balance cost vs. detection speed
- Configure threat intelligence feeds to reduce false positives
- Monitor GuardDuty usage in AWS Cost Explorer

## Compliance Mapping

### SOC 2 Type II
- **CC6.1**: Logical access controls through RBAC and IRSA
- **CC6.7**: Data transmission controls via encryption
- **CC7.2**: System monitoring through comprehensive logging

### PCI DSS
- **Requirement 10**: Audit logging of all access to cardholder data
- **Requirement 11**: Regular security testing through GuardDuty

### NIST Cybersecurity Framework
- **Detect (DE)**: Continuous monitoring and threat detection
- **Respond (RS)**: Automated alerting and incident response
- **Recover (RC)**: Audit trails for forensic analysis