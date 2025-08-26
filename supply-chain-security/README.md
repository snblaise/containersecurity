# Supply Chain Security Implementation

This directory contains a comprehensive supply chain security implementation for containerized applications on AWS, providing security gates, admission policies, and emergency override mechanisms.

## Overview

The supply chain security implementation provides:

- **CI/CD Security Gates**: SAST, SCA, and container image scanning with build failure logic
- **Admission Controller Policies**: Image provenance verification and signature validation
- **Emergency Override Mechanisms**: Controlled exceptions for incident response
- **Monitoring and Compliance**: Security metrics and audit trails

## Components

### 1. CI/CD Security Gates (`codepipeline/`)

Implements comprehensive security scanning in the CI/CD pipeline:

- **SAST Scanning**: Static application security testing with Semgrep
- **SCA Scanning**: Software composition analysis with Trivy
- **Container Scanning**: Image vulnerability scanning with build failure logic
- **Provenance Recording**: Build metadata and attestation generation
- **Security Metrics**: CloudWatch metrics for vulnerability tracking

#### Key Files:
- `buildspec-security-gates.yml`: CodeBuild specification for security scanning
- `pipeline-with-security-gates.tf`: Terraform configuration for secure pipeline
- `iam-roles.tf`: IAM roles and policies for pipeline security
- `monitoring-dashboard.tf`: CloudWatch dashboard for security metrics

### 2. Admission Controller Policies (`admission-policies/`)

Provides runtime security enforcement through admission controllers:

- **Kyverno Policies**: Image provenance and signature verification
- **Gatekeeper Policies**: Alternative OPA-based policy enforcement
- **Emergency Overrides**: Controlled exceptions with approval workflows
- **Policy Exemptions**: System namespace and emergency deployment handling

#### Key Files:
- `kyverno-image-provenance.yaml`: Kyverno policies for supply chain security
- `gatekeeper-image-policies.yaml`: Gatekeeper constraint templates and policies
- `emergency-override-policies.yaml`: Emergency deployment approval mechanisms

### 3. Scripts and Utilities (`scripts/`)

Automation and validation tools:

- **Security Metrics**: CloudWatch metrics publishing from build process
- **Emergency Approvals**: Command-line tool for emergency deployment approvals
- **Policy Validation**: Automated testing of admission policies

#### Key Files:
- `publish-security-metrics.sh`: Publishes security scan results to CloudWatch
- `emergency-deployment-approval.sh`: Emergency deployment approval workflow
- `validate-admission-policies.sh`: Automated testing of admission policies

## Quick Start

### 1. Deploy CI/CD Security Gates

```bash
# Configure Terraform variables
export TF_VAR_aws_account_id="123456789012"
export TF_VAR_repository_name="my-app-repo"
export TF_VAR_ecr_repository_name="my-app"
export TF_VAR_eks_cluster_name="my-cluster"

# Deploy pipeline infrastructure
cd codepipeline/
terraform init
terraform plan
terraform apply
```

### 2. Install Admission Controller Policies

Choose either Kyverno or Gatekeeper:

#### Option A: Kyverno
```bash
# Install Kyverno
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.10.0/install.yaml

# Apply supply chain policies
kubectl apply -f admission-policies/kyverno-image-provenance.yaml
kubectl apply -f admission-policies/emergency-override-policies.yaml
```

#### Option B: Gatekeeper
```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Apply supply chain policies
kubectl apply -f admission-policies/gatekeeper-image-policies.yaml
```

### 3. Configure Emergency Approvals

```bash
# Set up emergency approval configuration
kubectl apply -f admission-policies/emergency-override-policies.yaml

# Test emergency approval workflow
./scripts/emergency-deployment-approval.sh create deployment myapp production \
  security-lead@company.com "Critical security patch" INC-12345 security-incident 8h
```

### 4. Validate Implementation

```bash
# Run admission policy validation tests
./scripts/validate-admission-policies.sh

# Check security metrics
aws cloudwatch get-metric-statistics \
  --namespace SupplyChainSecurity \
  --metric-name CriticalVulnerabilities \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Maximum
```

## Security Gates Configuration

### Vulnerability Thresholds

The security gates enforce the following default thresholds:

- **Critical Vulnerabilities**: 0 (build fails)
- **High Vulnerabilities**: 5 (build fails if exceeded)
- **Medium Vulnerabilities**: 20 (build fails if exceeded)

These can be customized in the buildspec or Terraform variables.

### Scanning Tools

- **SAST**: Semgrep v1.45.0 for static code analysis
- **SCA**: Trivy v0.48.0 for dependency scanning
- **SBOM**: Syft v0.95.0 for software bill of materials
- **Signing**: Cosign v2.2.1 for image signing

## Admission Policy Configuration

### Image Registry Allowlist

By default, only ECR repositories are allowed:
- `*.dkr.ecr.*.amazonaws.com/*`
- Account-specific ECR repositories

### Signature Verification

Images must be signed with approved keys:
- Primary signing key for production images
- Secondary signing key for redundancy
- Emergency override for incident response

### Vulnerability Requirements

Images must have scan attestations showing:
- 0 critical vulnerabilities
- ≤5 high vulnerabilities
- ≤20 medium vulnerabilities

## Emergency Override Procedures

### Authorized Approvers

- **Security Team Lead**: 24h max duration, high approval level
- **CISO**: 72h max duration, critical approval level
- **Incident Commander**: 12h max duration, medium approval level
- **Platform Team Lead**: 8h max duration, low approval level

### Emergency Scenarios

- **security-incident**: Requires high approval level
- **production-outage**: Requires medium approval level
- **compliance-issue**: Requires critical approval level
- **vulnerability-patch**: Requires low approval level

### Usage Example

```bash
# Create emergency deployment
./scripts/emergency-deployment-approval.sh create deployment critical-app production \
  security-lead@company.com "Zero-day vulnerability patch" INC-54321 security-incident 12h

# List active emergency deployments
./scripts/emergency-deployment-approval.sh list

# Revoke emergency deployment
./scripts/emergency-deployment-approval.sh revoke deployment critical-app production "Incident resolved"
```

## Monitoring and Alerting

### CloudWatch Metrics

The implementation publishes the following metrics to the `SupplyChainSecurity` namespace:

- `CriticalVulnerabilities`: Number of critical vulnerabilities detected
- `HighVulnerabilities`: Number of high vulnerabilities detected
- `SASTIssues`: Number of SAST issues found
- `SCAIssues`: Number of SCA issues found
- `BuildsBlocked`: Number of builds blocked by security gates
- `SecurityGateFailures`: Number of security gate failures

### Alerts

CloudWatch alarms are configured for:
- Security gate build failures
- Critical vulnerability detection
- Emergency deployment approvals

### Dashboard

A CloudWatch dashboard provides visibility into:
- Build success/failure rates
- Vulnerability trends over time
- Security gate effectiveness
- Emergency deployment usage

## Compliance and Audit

### Audit Trails

All security events are logged:
- Security gate failures in CloudWatch Logs
- Admission policy violations in Kubernetes events
- Emergency deployments in audit logs
- Policy changes in Git history

### Compliance Reports

Generate compliance reports:

```bash
# Security scan report
./scripts/publish-security-metrics.sh report

# Admission policy test report
./scripts/validate-admission-policies.sh
```

## Troubleshooting

### Common Issues

1. **Build Failures Due to Vulnerabilities**
   - Review scan results in CloudWatch Logs
   - Update dependencies to fix vulnerabilities
   - Consider temporary threshold adjustment for critical fixes

2. **Admission Policy Rejections**
   - Verify image signatures and provenance
   - Check vulnerability scan results
   - Use emergency override for incidents

3. **Emergency Override Issues**
   - Verify approver is authorized
   - Check expiry time hasn't passed
   - Ensure proper annotations are present

### Debug Commands

```bash
# Check policy status
kubectl get clusterpolicy
kubectl get constrainttemplate

# View policy violations
kubectl get events --field-selector reason=PolicyViolation

# Check emergency deployments
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.metadata.annotations.security\.policy/emergency-override}{"\n"}{end}' | grep true
```

## Security Considerations

### Key Management

- Store signing keys securely in AWS KMS or HashiCorp Vault
- Rotate signing keys regularly
- Use separate keys for different environments

### Network Security

- Restrict access to build environments
- Use VPC endpoints for AWS service access
- Implement network policies for pod communication

### Access Control

- Limit emergency override approvers
- Use least-privilege IAM policies
- Audit approval workflows regularly

## Integration with Other Security Tools

### SIEM Integration

Forward security events to SIEM systems:
- CloudWatch Logs to Splunk/ELK
- Kubernetes events to security platforms
- Metrics to monitoring systems

### Vulnerability Management

Integrate with vulnerability management platforms:
- Export scan results to vulnerability databases
- Correlate findings across environments
- Track remediation progress

### Incident Response

Integrate with incident response workflows:
- Automatic ticket creation for security failures
- Escalation procedures for critical issues
- Communication channels for security teams

## Contributing

When contributing to this implementation:

1. Test changes in non-production environments
2. Update documentation for configuration changes
3. Validate security controls after modifications
4. Follow security best practices for code changes

## Support

For issues or questions:
- Review troubleshooting section
- Check CloudWatch Logs for detailed error messages
- Validate configuration against requirements
- Contact security team for policy exceptions