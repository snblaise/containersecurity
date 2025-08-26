# SBOM Generation and Image Signing Workflow

This module implements comprehensive Software Bill of Materials (SBOM) generation and container image signing workflows for supply chain security and provenance verification.

## Overview

The solution provides:

- **SBOM Generation**: Automated creation of SBOMs using Syft in multiple formats
- **Image Signing**: Integration with AWS Signer and cosign for image provenance
- **Attestation Management**: Creation and verification of security attestations
- **Admission Control**: Kubernetes policies to enforce signed images and SBOM requirements
- **CI/CD Integration**: Seamless integration with CodeBuild and other CI/CD systems

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Source Code   │    │   CI/CD Build   │    │   Container     │
│                 │    │                 │    │   Registry      │
│ • Dockerfile    │───▶│ • Build Image   │───▶│ • Store Image   │
│ • Dependencies  │    │ • Generate SBOM │    │ • Store SBOM    │
│ • Build Config  │    │ • Sign Image    │    │ • Store Sigs    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Attestations  │    │   AWS Signer    │    │   Kubernetes    │
│                 │    │                 │    │   Admission     │
│ • SBOM          │◀───│ • Sign Images   │    │   Controllers   │
│ • Vuln Scans    │    │ • Provenance    │───▶│ • Verify Sigs   │
│ • Provenance    │    │ • Certificates  │    │ • Check SBOM    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Components

### 1. SBOM Generation (`sbom-generation/`)

#### Generate SBOM Script (`generate-sbom.sh`)
Standalone script for generating SBOMs using Syft:

```bash
# Basic usage
./generate-sbom.sh my-app:latest

# With custom format and S3 upload
SBOM_FORMAT=cyclonedx-json SBOM_S3_BUCKET=my-sbom-bucket \
./generate-sbom.sh 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.2.3
```

**Features:**
- Multiple output formats (SPDX-JSON, CycloneDX, Syft-JSON)
- Automatic S3 upload for artifact storage
- Package counting and analysis
- CI/CD integration with environment variables
- Comprehensive error handling and validation

#### CodeBuild Integration (`buildspec-with-sbom.yml`)
Enhanced buildspec that includes SBOM generation in the build process:

```yaml
phases:
  install:
    commands:
      - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  build:
    commands:
      - docker build -t $IMAGE_REPO_NAME:$IMAGE_TAG .
      - syft $IMAGE_REPO_NAME:$IMAGE_TAG -o spdx-json=$SBOM_FILE
```

**Integration Points:**
- Automatic SBOM generation after image build
- S3 upload for long-term storage
- Attestation creation with build metadata
- Integration with vulnerability scanning
- Cosign signing for SBOM attestations

### 2. Image Signing (`image-signing/`)

#### AWS Signer Integration (`aws-signer-integration.sh`)
Script for signing container images using AWS Signer:

```bash
# Sign with AWS Signer
SIGNING_PROFILE_NAME=prod-signing \
./aws-signer-integration.sh 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.2.3

# Fallback to cosign if AWS Signer unavailable
./aws-signer-integration.sh my-registry/my-app:latest
```

**Features:**
- AWS Signer profile management
- Automatic fallback to cosign
- Provenance metadata generation
- Attestation creation and signing
- S3 artifact storage

#### Terraform Configuration (`terraform/aws-signer.tf`)
Infrastructure as Code for AWS Signer setup:

```hcl
resource "aws_signer_signing_profile" "container_signing" {
  platform_id = "AWSLambda-SHA256-ECDSA"
  name        = var.signing_profile_name
  
  signature_validity_period {
    value = var.signature_validity_days
    type  = "DAYS"
  }
}
```

**Resources Created:**
- AWS Signer signing profile
- S3 bucket for signing artifacts
- KMS keys for encryption
- IAM roles and policies
- EventBridge rules for signing events
- Lambda function for event processing

### 3. Admission Control Policies (`admission-policies/`)

#### Kyverno Policies (`kyverno-image-verification.yaml`)
Comprehensive policies for image verification:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature-verification
spec:
  validationFailureAction: enforce
  rules:
    - name: verify-image-signatures
      verifyImages:
      - imageReferences: ["*"]
        attestors:
        - entries:
          - keys:
              publicKeys: |-
                -----BEGIN PUBLIC KEY-----
                ...
                -----END PUBLIC KEY-----
```

**Policy Types:**
- Image signature verification
- SBOM attestation requirements
- Vulnerability scan validation
- Provenance verification
- Trusted registry enforcement

#### Gatekeeper Policies (`gatekeeper-image-policies.yaml`)
Alternative OPA-based policies for environments using Gatekeeper:

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: requireimagesignature
spec:
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package requireimagesignature
        
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not has_signature_annotation
          msg := "Container image must be signed"
        }
```

**Constraint Types:**
- RequireImageSignature
- RequireSBOMAttestation
- RequireVulnerabilityScan
- RequireImageProvenance

#### Validation Script (`validate-admission-policies.sh`)
Automated testing for admission policies:

```bash
# Test Kyverno policies
./validate-admission-policies.sh --engine kyverno

# Test Gatekeeper policies
./validate-admission-policies.sh --engine gatekeeper --namespace test-policies
```

**Test Scenarios:**
- Block unsigned images
- Allow properly signed images
- Block images with high vulnerabilities
- Verify policy exceptions
- Check policy status and health

## Configuration

### Environment Variables

```bash
# SBOM Generation
SBOM_FORMAT=spdx-json                    # Output format
SBOM_OUTPUT_DIR=./sbom-reports          # Local output directory
SBOM_S3_BUCKET=my-sbom-bucket           # S3 bucket for storage

# Image Signing
SIGNING_PROFILE_NAME=container-signing   # AWS Signer profile
SIGNING_PLATFORM_ID=AWSLambda-SHA256-ECDSA  # Platform ID
SIGNING_ARTIFACTS_BUCKET=my-signing-artifacts  # S3 bucket

# Policy Configuration
POLICY_ENGINE=kyverno                    # kyverno or gatekeeper
TEST_NAMESPACE=policy-test               # Test namespace
```

### AWS Parameter Store

Store configuration in Parameter Store for CI/CD access:

```bash
# SBOM configuration
aws ssm put-parameter \
  --name "/container-security/sbom/s3-bucket" \
  --value "my-sbom-bucket" \
  --type "String"

# Signing configuration
aws ssm put-parameter \
  --name "/container-security/signing/profile-name" \
  --value "production-signing" \
  --type "String"
```

## Usage Workflows

### 1. CI/CD Integration

#### CodeBuild Project Setup
```yaml
version: 0.2
env:
  variables:
    SBOM_FORMAT: "spdx-json"
    SBOM_S3_BUCKET: "my-sbom-bucket"
  parameter-store:
    SIGNING_PROFILE_NAME: "/container-security/signing/profile-name"

phases:
  install:
    commands:
      - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
      - curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
      - mv cosign-linux-amd64 /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign

  build:
    commands:
      - docker build -t $IMAGE_NAME .
      - syft $IMAGE_NAME -o $SBOM_FORMAT=$SBOM_FILE
      - cosign sign --key cosign.key $IMAGE_NAME
      - cosign attest --key cosign.key --predicate $SBOM_FILE $IMAGE_NAME
```

### 2. Manual SBOM Generation

```bash
# Generate SBOM for local image
./sbom-generation/generate-sbom.sh my-app:latest

# Generate SBOM for remote image with S3 upload
SBOM_S3_BUCKET=my-bucket \
./sbom-generation/generate-sbom.sh 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.2.3

# Generate multiple formats
for format in spdx-json cyclonedx-json syft-json; do
  SBOM_FORMAT=$format ./sbom-generation/generate-sbom.sh my-app:latest
done
```

### 3. Image Signing Workflow

```bash
# Sign with AWS Signer
SIGNING_PROFILE_NAME=prod-signing \
./image-signing/aws-signer-integration.sh my-registry/my-app:v1.2.3

# Sign with cosign (fallback)
cosign generate-key-pair
cosign sign --key cosign.key my-registry/my-app:v1.2.3

# Create and sign attestations
cosign attest --key cosign.key --predicate sbom.json my-registry/my-app:v1.2.3
cosign attest --key cosign.key --predicate provenance.json my-registry/my-app:v1.2.3
```

### 4. Policy Deployment

```bash
# Deploy Kyverno policies
kubectl apply -f admission-policies/kyverno-image-verification.yaml

# Deploy Gatekeeper policies
kubectl apply -f admission-policies/gatekeeper-image-policies.yaml

# Validate policies
./admission-policies/validate-admission-policies.sh --engine kyverno
```

## Security Considerations

### Key Management

1. **AWS Signer**: Uses AWS-managed keys with automatic rotation
2. **Cosign Keys**: Store private keys securely in AWS Secrets Manager
3. **Public Keys**: Distribute via secure channels and embed in policies

### Access Control

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/CodeBuildRole"
      },
      "Action": [
        "signer:StartSigningJob",
        "signer:DescribeSigningJob"
      ],
      "Resource": "arn:aws:signer:REGION:ACCOUNT:signing-profile/PROFILE"
    }
  ]
}
```

### Network Security

- Use VPC endpoints for AWS Signer access
- Implement network policies for admission controllers
- Secure S3 buckets with bucket policies and encryption

## Monitoring and Alerting

### CloudWatch Metrics

- SBOM generation success/failure rates
- Image signing job completion times
- Policy violation counts
- Attestation verification failures

### SNS Notifications

```json
{
  "image": "my-app:v1.2.3",
  "event": "signing_completed",
  "status": "success",
  "signing_profile": "production-signing",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Dashboard Metrics

- Percentage of signed images in production
- SBOM coverage across repositories
- Policy violation trends
- Mean time to signature verification

## Troubleshooting

### Common Issues

1. **SBOM Generation Fails**
   ```bash
   # Check syft installation
   syft version
   
   # Verify image accessibility
   docker pull $IMAGE_NAME
   
   # Check S3 permissions
   aws s3 ls s3://$SBOM_S3_BUCKET/
   ```

2. **Signing Job Failures**
   ```bash
   # Check signing profile
   aws signer get-signing-profile --profile-name $PROFILE_NAME
   
   # Verify IAM permissions
   aws sts get-caller-identity
   
   # Check signing job status
   aws signer describe-signing-job --job-id $JOB_ID
   ```

3. **Policy Violations**
   ```bash
   # Check policy status
   kubectl get clusterpolicies
   
   # View policy violations
   kubectl get events --field-selector reason=PolicyViolation
   
   # Test policy with dry-run
   kubectl apply --dry-run=server -f test-pod.yaml
   ```

### Debug Commands

```bash
# Verify image signatures
cosign verify --key cosign.pub $IMAGE_NAME

# Check SBOM attestations
cosign verify-attestation --key cosign.pub $IMAGE_NAME

# List all attestations
cosign tree $IMAGE_NAME

# Validate SBOM format
syft $SBOM_FILE -o table
```

## Compliance and Reporting

### SLSA Compliance

The workflow supports SLSA (Supply-chain Levels for Software Artifacts) requirements:

- **Level 1**: Provenance generation and storage
- **Level 2**: Tamper-resistant build environment (CodeBuild)
- **Level 3**: Hardened build platform with verified provenance

### Audit Trail

All operations generate audit logs:
- CloudTrail for AWS API calls
- CodeBuild logs for build operations
- Kubernetes audit logs for policy decisions
- S3 access logs for artifact retrieval

### Reporting

Generate compliance reports:
```bash
# SBOM coverage report
aws s3 ls s3://my-sbom-bucket/sbom-reports/ --recursive | wc -l

# Signing status report
aws signer list-signing-jobs --status Succeeded --max-results 100

# Policy compliance report
kubectl get events --field-selector reason=PolicyViolation -o json | \
  jq '.items | length'
```

## Integration Examples

### GitHub Actions

```yaml
name: Build and Sign
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Generate SBOM
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft . -o spdx-json=sbom.json
      - name: Sign image
        run: |
          cosign sign --key ${{ secrets.COSIGN_PRIVATE_KEY }} $IMAGE_NAME
          cosign attest --key ${{ secrets.COSIGN_PRIVATE_KEY }} --predicate sbom.json $IMAGE_NAME
```

### GitLab CI

```yaml
stages:
  - build
  - sign
  - deploy

generate-sbom:
  stage: build
  script:
    - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    - syft $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -o spdx-json=sbom.json
  artifacts:
    paths:
      - sbom.json

sign-image:
  stage: sign
  script:
    - cosign sign --key $COSIGN_PRIVATE_KEY $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - cosign attest --key $COSIGN_PRIVATE_KEY --predicate sbom.json $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

This comprehensive SBOM and image signing workflow provides enterprise-grade supply chain security with full attestation and verification capabilities.