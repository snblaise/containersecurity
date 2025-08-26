# Container Security Compliance Validation

This directory contains comprehensive validation scripts for container security compliance, implementing automated testing for security policies, CIS Kubernetes Benchmark alignment, and continuous compliance monitoring.

## Scripts Overview

### 1. Security Policy Compliance (`security-policy-compliance.sh`)
Validates security policy compliance across EKS clusters including:
- Pod Security Admission policy enforcement
- Security contexts in pods and containers
- Network policy implementation
- RBAC configuration
- Image security practices
- Secrets management

### 2. CIS Kubernetes Benchmark (`cis-kubernetes-benchmark.sh`)
Implements CIS Kubernetes Benchmark v1.8 validation for:
- Privileged container restrictions
- Host namespace sharing controls
- Privilege escalation prevention
- Root container minimization
- Capability restrictions
- Network policy enforcement
- Administrative boundaries

### 3. Continuous Compliance Monitor (`continuous-compliance-monitor.sh`)
Orchestrates comprehensive compliance monitoring by:
- Running all compliance checks periodically
- Integrating with AWS Config rules
- Monitoring GuardDuty findings
- Generating combined compliance reports
- Sending notifications via webhooks and email

## Usage Examples

### Security Policy Compliance Check
```bash
# Basic compliance check
./security-policy-compliance.sh --cluster production-eks

# Detailed check with table output
./security-policy-compliance.sh --cluster staging-eks --format table --verbose

# Custom compliance threshold
./security-policy-compliance.sh --cluster dev-eks --threshold 95 --format yaml
```

### CIS Kubernetes Benchmark
```bash
# Run CIS benchmark validation
./cis-kubernetes-benchmark.sh --cluster production-eks

# Specific CIS version with verbose output
./cis-kubernetes-benchmark.sh --cluster staging-eks --version 1.7 --verbose

# Table format output
./cis-kubernetes-benchmark.sh --cluster dev-eks --format table
```

### Continuous Compliance Monitoring
```bash
# Run once and exit
./continuous-compliance-monitor.sh --cluster production-eks --once

# Run as daemon with 30-minute intervals
./continuous-compliance-monitor.sh --cluster production-eks --daemon --interval 1800

# With notifications
./continuous-compliance-monitor.sh \
  --cluster production-eks \
  --daemon \
  --webhook https://hooks.slack.com/services/... \
  --email security-team@company.com,compliance@company.com
```

## Configuration

### Environment Variables
```bash
# Cluster configuration
export CLUSTER_NAME="production-eks"
export COMPLIANCE_THRESHOLD=85

# Monitoring configuration
export MONITORING_INTERVAL=3600
export OUTPUT_DIR="/var/log/compliance-reports"

# Notification configuration
export WEBHOOK_URL="https://hooks.slack.com/services/..."
export EMAIL_RECIPIENTS="security@company.com,compliance@company.com"
```

### Prerequisites
- `kubectl` configured for target EKS cluster
- `jq` for JSON processing
- `yq` for YAML processing (optional)
- `aws` CLI configured with appropriate permissions
- `curl` for webhook notifications

### Required AWS Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "eks:DescribeCluster",
                "eks:ListClusters",
                "config:GetComplianceDetailsByConfigRule",
                "config:DescribeConfigRules",
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "ses:SendEmail"
            ],
            "Resource": "*"
        }
    ]
}
```

## Output Formats

### JSON Output (Default)
```json
{
  "cluster_name": "production-eks",
  "timestamp": "2024-01-15T10:30:00Z",
  "compliance_threshold": 90,
  "checks": [
    {
      "name": "Pod Security Admission",
      "status": "PASS",
      "message": "PSA is enabled with 5/6 namespaces using restricted policy",
      "severity": "HIGH",
      "remediation": "",
      "timestamp": "2024-01-15T10:30:15Z"
    }
  ],
  "summary": {
    "total_checks": 6,
    "passed_checks": 5,
    "failed_checks": 1,
    "compliance_percentage": 83,
    "overall_status": "NON_COMPLIANT"
  }
}
```

### Table Output
```
Container Security Compliance Report
====================================
Cluster: production-eks
Namespace: default
Timestamp: 2024-01-15T10:30:00Z

Overall Status: COMPLIANT (92%)

Check Name                     Status     Message
----------                     ------     -------
Pod Security Admission         PASS       PSA enabled with restricted policy
Security Contexts              PASS       45/45 pods have security contexts
Network Policies               FAIL       Only 3/6 namespaces have policies
RBAC Configuration             PASS       Limited cluster-admin bindings
Image Security                 PASS       No :latest tags, 44/45 non-root
Secrets Management             PASS       No env secrets, 12 CSI secrets
```

### YAML Output
```yaml
cluster_name: production-eks
timestamp: "2024-01-15T10:30:00Z"
compliance_threshold: 90
checks:
  - name: Pod Security Admission
    status: PASS
    message: PSA is enabled with 5/6 namespaces using restricted policy
    severity: HIGH
    remediation: ""
    timestamp: "2024-01-15T10:30:15Z"
summary:
  total_checks: 6
  passed_checks: 5
  failed_checks: 1
  compliance_percentage: 83
  overall_status: NON_COMPLIANT
```

## Compliance Checks Detail

### Security Policy Compliance Checks

#### Pod Security Admission
- **Check**: Validates PSA is enabled with restricted policies
- **Requirement**: All namespaces should use restricted PSA policy
- **Remediation**: Enable Pod Security Admission with restricted enforcement

#### Security Contexts
- **Check**: Ensures pods have proper securityContext configurations
- **Requirement**: 90%+ pods should have securityContext, no privileged containers
- **Remediation**: Add securityContext to pod specifications

#### Network Policies
- **Check**: Validates network policy implementation
- **Requirement**: 90%+ namespaces should have network policies with default-deny
- **Remediation**: Implement network policies for all application namespaces

#### RBAC Configuration
- **Check**: Reviews role-based access control setup
- **Requirement**: Limited cluster-admin bindings, service accounts with RBAC
- **Remediation**: Review and minimize cluster-admin role bindings

#### Image Security
- **Check**: Validates container image security practices
- **Requirement**: No :latest tags, 90%+ containers run as non-root
- **Remediation**: Use specific image tags and enable runAsNonRoot

#### Secrets Management
- **Check**: Ensures secure secrets handling
- **Requirement**: No secrets in environment variables, use CSI driver
- **Remediation**: Migrate to Secrets Store CSI driver

### CIS Kubernetes Benchmark Controls

#### 5.1.1 - Minimize Privileged Containers
- **Check**: No containers with privileged: true
- **Level**: 1 (Scored)
- **Remediation**: Remove privileged: true from container specifications

#### 5.1.2 - Minimize Host PID Namespace Sharing
- **Check**: No containers with hostPID: true
- **Level**: 1 (Scored)
- **Remediation**: Remove hostPID: true from pod specifications

#### 5.1.3 - Minimize Host IPC Namespace Sharing
- **Check**: No containers with hostIPC: true
- **Level**: 1 (Scored)
- **Remediation**: Remove hostIPC: true from pod specifications

#### 5.1.4 - Minimize Host Network Namespace Sharing
- **Check**: Only system pods should use hostNetwork: true
- **Level**: 1 (Scored)
- **Remediation**: Remove hostNetwork: true from non-system pods

#### 5.1.5 - Minimize allowPrivilegeEscalation
- **Check**: No containers with allowPrivilegeEscalation: true
- **Level**: 1 (Scored)
- **Remediation**: Set allowPrivilegeEscalation: false

#### 5.1.6 - Minimize Root Containers
- **Check**: 80%+ containers should run as non-root
- **Level**: 1 (Scored)
- **Remediation**: Set runAsNonRoot: true or runAsUser to non-zero

#### 5.2.1 - Minimize Container Capabilities
- **Check**: No containers should have added capabilities
- **Level**: 1 (Scored)
- **Remediation**: Use drop: ["ALL"] in securityContext

#### 5.3.1 - Ensure CNI Supports Network Policies
- **Check**: Network policies exist and CNI supports them
- **Level**: 1 (Scored)
- **Remediation**: Install CNI that supports network policies

#### 5.3.2 - Ensure All Namespaces Have Network Policies
- **Check**: 80%+ user namespaces should have network policies
- **Level**: 1 (Scored)
- **Remediation**: Create network policies for all namespaces

#### 5.7.1 - Administrative Boundaries Using Namespaces
- **Check**: Multiple namespaces exist, default namespace is empty
- **Level**: 1 (Scored)
- **Remediation**: Create separate namespaces for applications

## Integration with CI/CD

### GitLab CI Example
```yaml
compliance_check:
  stage: security
  script:
    - ./monitoring-compliance/validation/security-policy-compliance.sh --cluster $CLUSTER_NAME --format json
    - ./monitoring-compliance/validation/cis-kubernetes-benchmark.sh --cluster $CLUSTER_NAME --format json
  artifacts:
    reports:
      junit: compliance-report.xml
    paths:
      - compliance-reports/
  only:
    - main
    - develop
```

### GitHub Actions Example
```yaml
name: Container Security Compliance
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
  workflow_dispatch:

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - name: Run compliance checks
        run: |
          ./monitoring-compliance/validation/continuous-compliance-monitor.sh \
            --cluster production-eks \
            --once \
            --webhook ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Troubleshooting

### Common Issues

#### kubectl Connection Errors
```bash
# Check kubectl configuration
kubectl cluster-info

# Update kubeconfig for EKS
aws eks update-kubeconfig --region us-east-1 --name production-eks
```

#### AWS Permissions Errors
```bash
# Check AWS credentials
aws sts get-caller-identity

# Test specific permissions
aws config describe-config-rules
aws guardduty list-detectors
```

#### Missing Dependencies
```bash
# Install required tools on Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y jq curl

# Install yq
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod +x /usr/local/bin/yq

# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

### Log Analysis

#### Debug Mode
```bash
# Enable verbose output
export VERBOSE=true
./security-policy-compliance.sh --cluster production-eks --verbose

# Check specific namespace
./security-policy-compliance.sh --cluster production-eks --namespace kube-system
```

#### Log Locations
- Compliance reports: `/tmp/compliance-reports/` (default)
- Script logs: stderr output
- AWS Config logs: CloudWatch Logs
- GuardDuty findings: GuardDuty console

## Metrics and KPIs

### Compliance Metrics
- **Overall Compliance Score**: Weighted average of all checks
- **Security Policy Compliance**: Percentage of passed security checks
- **CIS Benchmark Score**: Percentage of passed CIS controls
- **AWS Config Compliance**: Percentage of compliant Config rules

### Security Metrics
- **Mean Time to Remediation (MTTR)**: Time to fix compliance violations
- **Policy Violation Rate**: Number of violations per deployment
- **Critical Finding Response Time**: Time to address critical GuardDuty findings
- **Compliance Trend**: Compliance score over time

### Alerting Thresholds
- **Critical**: Compliance score < 70% or critical GuardDuty findings
- **Warning**: Compliance score < 85% or high GuardDuty findings
- **Info**: Compliance score >= 85% and no high-severity findings

## Best Practices

### Scheduling
- Run compliance checks daily during off-peak hours
- Use different intervals for different environments (prod: 4h, staging: 8h, dev: 24h)
- Implement circuit breakers to prevent alert fatigue

### Reporting
- Store historical compliance data for trend analysis
- Create dashboards for real-time compliance visibility
- Generate weekly/monthly compliance reports for stakeholders

### Remediation
- Automate remediation for low-risk violations
- Create runbooks for manual remediation procedures
- Track remediation efforts and measure effectiveness

### Integration
- Integrate with existing SIEM and monitoring systems
- Use compliance data for risk assessment and audit preparation
- Correlate compliance violations with security incidents