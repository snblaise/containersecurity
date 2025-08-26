# Secrets Management Validation Scripts

This directory contains validation scripts to ensure proper secrets management implementation and security compliance.

## Scripts Overview

### 1. validate-secrets-not-in-images.sh
Comprehensive script to scan container images for embedded secrets and sensitive data.

**Features:**
- Trivy integration for secrets scanning
- Filesystem analysis for secret patterns
- Environment variable inspection
- Support for single image or Kubernetes manifest scanning
- Detailed JSON reporting

**Usage:**
```bash
# Scan images from Kubernetes manifests (default)
./validate-secrets-not-in-images.sh manifests ../pod-examples

# Scan a single image
./validate-secrets-not-in-images.sh image myregistry/myapp:latest

# Scan with custom ECR registry
ECR_REGISTRY=123456789012.dkr.ecr.us-east-1.amazonaws.com ./validate-secrets-not-in-images.sh
```

**Secret Patterns Detected:**
- Password and secret environment variables
- API keys and tokens
- Private keys and certificates
- AWS credentials (Access Key ID patterns)
- Database connection strings
- JWT signing keys

### 2. test-secrets-injection.sh
Functional testing script to validate secrets injection in running pods.

**Features:**
- Pod readiness validation
- Secrets Store CSI volume mounting verification
- Environment variable injection testing
- IRSA (IAM Roles for Service Accounts) functionality testing
- Comprehensive test reporting

**Usage:**
```bash
# Test database application secrets
./test-secrets-injection.sh database-app

# Test web application secrets
./test-secrets-injection.sh web-app

# Test monitoring stack secrets
./test-secrets-injection.sh monitoring

# Use custom kubectl context
KUBECTL_CONTEXT=my-cluster ./test-secrets-injection.sh database-app
```

**Test Categories:**
- Mount path existence and content verification
- Environment variable presence and value validation
- CSI driver volume mounting
- IRSA token and role configuration

## Prerequisites

### For validate-secrets-not-in-images.sh:
- Docker CLI
- Trivy security scanner
- jq for JSON processing
- Access to container registry

### For test-secrets-injection.sh:
- kubectl CLI configured for target cluster
- jq for JSON processing
- bc for calculations
- Running pods with secrets configuration

## Installation of Dependencies

### Install Trivy (for secrets scanning):
```bash
# macOS
brew install aquasecurity/trivy/trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Or using package managers
apt-get install trivy  # Debian/Ubuntu
yum install trivy      # RHEL/CentOS
```

### Install jq:
```bash
# macOS
brew install jq

# Linux
apt-get install jq     # Debian/Ubuntu
yum install jq         # RHEL/CentOS
```

## Security Validation Workflow

1. **Pre-deployment Validation:**
   ```bash
   # Scan all images in pod examples
   ./validate-secrets-not-in-images.sh manifests ../pod-examples
   ```

2. **Post-deployment Testing:**
   ```bash
   # Test each application type
   ./test-secrets-injection.sh database-app
   ./test-secrets-injection.sh web-app
   ./test-secrets-injection.sh monitoring
   ```

3. **Continuous Monitoring:**
   - Integrate scripts into CI/CD pipelines
   - Schedule regular validation runs
   - Monitor for new secret patterns

## Report Formats

### Secrets Scanning Report:
```json
{
  "scan_summary": {
    "total_images": 3,
    "failed_scans": 0,
    "passed_scans": 3,
    "overall_status": "PASS"
  },
  "image_reports": [...]
}
```

### Injection Testing Report:
```json
{
  "test_summary": {
    "total_tests": 8,
    "passed": 8,
    "failed": 0,
    "success_rate": 100.00,
    "overall_status": "PASS"
  },
  "detailed_results": [...]
}
```

## Integration with CI/CD

### GitLab CI Example:
```yaml
secrets_validation:
  stage: security
  script:
    - ./validation/validate-secrets-not-in-images.sh manifests pod-examples
  artifacts:
    reports:
      junit: secrets-scan-report-*.json
```

### GitHub Actions Example:
```yaml
- name: Validate Secrets Not In Images
  run: |
    ./kubernetes-security/secrets-management/validation/validate-secrets-not-in-images.sh manifests kubernetes-security/secrets-management/pod-examples
```

## Troubleshooting

### Common Issues:

1. **Trivy scan failures:**
   - Ensure Docker daemon is running
   - Check image accessibility and credentials
   - Verify Trivy database is updated

2. **Pod testing failures:**
   - Verify pod is running and ready
   - Check RBAC permissions for kubectl
   - Ensure Secrets Store CSI driver is installed

3. **IRSA testing failures:**
   - Verify service account annotations
   - Check IAM role trust policy
   - Ensure OIDC provider is configured

### Debug Mode:
Set environment variables for additional logging:
```bash
export DEBUG=1
export VERBOSE=1
./validate-secrets-not-in-images.sh
```

## Security Best Practices

1. **Regular Scanning:**
   - Run validation scripts before each deployment
   - Schedule weekly comprehensive scans
   - Monitor for new secret patterns

2. **Fail-Fast Approach:**
   - Configure CI/CD to fail on any secret detection
   - Implement mandatory security reviews
   - Use admission controllers for runtime enforcement

3. **Audit Trail:**
   - Store all scan reports for compliance
   - Track remediation efforts
   - Monitor trends in secret exposure

4. **Team Training:**
   - Educate developers on secure practices
   - Provide clear guidelines for secrets handling
   - Regular security awareness sessions