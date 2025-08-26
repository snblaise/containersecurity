# AWS Container Security Implementation Guide

A comprehensive container security solution for regulated financial services environments on AWS, implementing defense-in-depth across the entire container lifecycle from image building through runtime security in Amazon EKS.

## Overview

This implementation provides enterprise-grade container security controls that address the unique requirements of regulated industries. The solution leverages AWS-native services to implement multiple security layers including supply chain security, runtime protection, infrastructure hardening, identity management, and comprehensive monitoring.

### Complete Solution Architecture

The solution implements a layered security approach across ten critical security domains:

1. **[Container Image Security](#1-container-image-security-layer)**: Multi-stage builds, vulnerability scanning, and secure base images
2. **[Kubernetes Runtime Security](#2-kubernetes-security-layer)**: Pod Security Admission, security contexts, and RBAC
3. **[Infrastructure Security](#3-infrastructure-security-layer)**: Node hardening, VPC design, and encryption
4. **[Identity & Access Management](#4-identity-and-access-management)**: IRSA implementation and least-privilege access
5. **[Secrets Management](#5-secrets-management)**: CSI driver integration and KMS encryption
6. **[Network Security](#network-security)**: Microsegmentation, egress filtering, and VPC endpoints
7. **[Supply Chain Security](#supply-chain-security)**: SBOM generation, image signing, and CI/CD gates
8. **[Image Security Scanning](#image-security-scanning)**: ECR integration, Inspector automation, and vulnerability management
9. **[Monitoring & Compliance](#monitoring-compliance)**: GuardDuty, CloudTrail, and continuous compliance
10. **[Validation Framework](#validation-framework)**: Automated testing, incident response, and security metrics

### Key Features

- **Zero-Trust Container Security**: Default-deny policies with explicit allow rules
- **Automated Vulnerability Management**: CI/CD integrated scanning with build failure thresholds
- **Secrets Management**: Runtime secrets injection without image embedding
- **Network Microsegmentation**: Pod-level network policies and security group controls
- **Supply Chain Protection**: SBOM generation, image signing, and provenance verification
- **Compliance Automation**: CIS Kubernetes Benchmark alignment and continuous monitoring
- **Incident Response Integration**: Automated threat detection and response capabilities
- **Comprehensive Validation**: End-to-end security testing and compliance verification

## Component Directory Structure

```
aws-container-security/
├── base-images/                    # Secure base image templates
├── examples/                       # Secure Dockerfile examples
├── kubernetes-security/            # K8s security configurations
│   ├── pod-security-admission/     # PSA policies and validation
│   ├── security-context-examples/  # Security context templates
│   ├── secrets-management/         # CSI driver and KMS integration
│   ├── network-policies/           # NetworkPolicy configurations
│   ├── irsa-templates/             # IRSA setup and examples
│   └── security-groups-for-pods/   # SGP configurations
├── image-security-scanning/        # ECR and Inspector integration
│   ├── terraform/                  # Infrastructure as code
│   ├── lambda/                     # Scan result processing
│   ├── codebuild/                  # CI/CD integration
│   ├── admission-policies/         # Image verification policies
│   └── sbom-generation/            # SBOM creation workflows
├── supply-chain-security/          # Supply chain protection
│   ├── codepipeline/               # Secure CI/CD pipelines
│   ├── admission-policies/         # Provenance verification
│   └── scripts/                    # Validation and metrics
├── network-security/               # Network isolation and filtering
│   ├── security-groups/            # Security group configurations
│   ├── vpc-endpoints/              # VPC endpoint setup
│   ├── aws-network-firewall/       # Egress filtering rules
│   └── dns-filtering/              # DNS-based access control
├── iaas-security/                  # Infrastructure security
│   ├── terraform/                  # VPC, KMS, and cluster config
│   ├── ssm-documents/              # Node hardening automation
│   └── scripts/                    # Deployment and validation
├── monitoring-compliance/          # Monitoring and compliance
│   ├── aws-config/                 # Compliance rules
│   ├── cloudtrail/                 # Audit logging
│   ├── cloudwatch/                 # Metrics and alarms
│   ├── guardduty/                  # Threat detection
│   └── validation/                 # Compliance testing
└── validation-framework/           # Testing and validation
    ├── comprehensive-validation.sh # Complete security testing
    ├── incident-response-procedures.md
    ├── vulnerability-mttr-tracking.md
    └── admission-policy-validation.md
```

## Quick Start Guide

### Prerequisites

- **AWS Account**: Administrative permissions for EKS, ECR, IAM, VPC, and security services
- **Amazon EKS Cluster**: Version 1.24+ with OIDC provider enabled
- **AWS CLI**: Version 2.x configured with appropriate credentials
- **kubectl**: Compatible with your EKS cluster version
- **Container Tools**: Docker, Helm 3.x, and container registry access
- **Infrastructure Tools**: Terraform 1.5+ (optional but recommended)
- **Security Tools**: Falco, OPA Gatekeeper, or Kyverno for policy enforcement

### Deployment Considerations

- **Network Architecture**: Private subnets with NAT Gateway or VPC endpoints for internet access
- **Encryption**: Customer-managed KMS keys for all encryption at rest
- **Monitoring**: CloudTrail, GuardDuty, and Config enabled across all regions
- **Compliance**: Ensure alignment with SOC 2, PCI DSS, or industry-specific requirements

### Complete Implementation Workflow

#### Phase 1: Infrastructure Foundation
```bash
# 1. Deploy VPC and EKS infrastructure
cd iaas-security/terraform
terraform init && terraform plan && terraform apply

# 2. Configure node hardening
./iaas-security/scripts/deploy-node-security.sh

# 3. Enable encryption and monitoring
kubectl apply -f iaas-security/kms/
```

#### Phase 2: Container Security Setup
```bash
# 1. Build secure base images
docker build -f base-images/alpine-nonroot.Dockerfile -t secure-base:alpine .
docker build -f base-images/ubuntu-nonroot.Dockerfile -t secure-base:ubuntu .

# 2. Validate Docker security configuration
./scripts/validate-docker-security.sh secure-base:alpine

# 3. Set up ECR repositories with scanning
cd image-security-scanning/terraform
terraform init && terraform apply
```

#### Phase 3: Kubernetes Security Configuration
```bash
# 1. Apply Pod Security Admission policies
kubectl apply -f kubernetes-security/pod-security-admission/

# 2. Configure security contexts and RBAC
kubectl apply -f kubernetes-security/security-context-examples/

# 3. Set up IRSA for service accounts
./kubernetes-security/irsa-templates/setup-irsa.sh

# 4. Deploy secrets management
kubectl apply -f kubernetes-security/secrets-management/secret-provider-classes/
```

#### Phase 4: Network Security Implementation
```bash
# 1. Apply network policies
kubectl apply -f kubernetes-security/network-policies/

# 2. Configure Security Groups for Pods
cd kubernetes-security/security-groups-for-pods
terraform init && terraform apply

# 3. Set up network firewall and VPC endpoints
cd network-security
terraform init && terraform apply
```

#### Phase 5: Supply Chain Security
```bash
# 1. Deploy CI/CD security gates
cd supply-chain-security/codepipeline
terraform init && terraform apply

# 2. Configure admission policies for image verification
kubectl apply -f supply-chain-security/admission-policies/

# 3. Set up SBOM generation
./image-security-scanning/sbom-generation/generate-sbom.sh
```

#### Phase 6: Monitoring and Compliance
```bash
# 1. Deploy monitoring infrastructure
cd monitoring-compliance
terraform init && terraform apply

# 2. Configure compliance rules
kubectl apply -f monitoring-compliance/aws-config/

# 3. Run comprehensive validation
./validation-framework/comprehensive-validation.sh
```

### Component Usage Instructions

#### [Container Image Security](./examples/)
- **Secure Dockerfiles**: Use [examples/secure-multistage.Dockerfile](./examples/secure-multistage.Dockerfile) for multi-stage builds
- **Base Images**: Deploy from [base-images/](./base-images/) for hardened foundations
- **Validation**: Run [scripts/validate-docker-security.sh](./scripts/validate-docker-security.sh) for compliance checking

#### [Kubernetes Security](./kubernetes-security/)
- **Pod Security**: Apply [pod-security-admission/](./kubernetes-security/pod-security-admission/) policies
- **Security Contexts**: Use [security-context-examples/](./kubernetes-security/security-context-examples/) templates
- **IRSA Setup**: Follow [irsa-templates/setup-irsa.sh](./kubernetes-security/irsa-templates/setup-irsa.sh)
- **Network Policies**: Deploy [network-policies/](./kubernetes-security/network-policies/) for microsegmentation
- **Secrets Management**: Configure [secrets-management/](./kubernetes-security/secrets-management/) CSI integration

#### [Image Security Scanning](./image-security-scanning/)
- **ECR Integration**: Deploy [terraform/ecr-repository.tf](./image-security-scanning/terraform/ecr-repository.tf)
- **Scan Automation**: Use [inspector-automation/scan-automation.sh](./image-security-scanning/inspector-automation/scan-automation.sh)
- **SBOM Generation**: Run [sbom-generation/generate-sbom.sh](./image-security-scanning/sbom-generation/generate-sbom.sh)
- **Admission Policies**: Apply [admission-policies/](./image-security-scanning/admission-policies/) for verification

#### [Supply Chain Security](./supply-chain-security/)
- **CI/CD Pipelines**: Deploy [codepipeline/pipeline-with-security-gates.tf](./supply-chain-security/codepipeline/pipeline-with-security-gates.tf)
- **Provenance Verification**: Use [admission-policies/kyverno-image-provenance.yaml](./supply-chain-security/admission-policies/kyverno-image-provenance.yaml)
- **Security Metrics**: Run [scripts/publish-security-metrics.sh](./supply-chain-security/scripts/publish-security-metrics.sh)

#### [Network Security](./network-security/)
- **VPC Configuration**: Deploy [vpc-subnets/private-subnets.tf](./network-security/vpc-subnets/private-subnets.tf)
- **Security Groups**: Apply [security-groups/eks-security-groups.tf](./network-security/security-groups/eks-security-groups.tf)
- **Network Firewall**: Configure [aws-network-firewall/firewall-rules.tf](./network-security/aws-network-firewall/firewall-rules.tf)
- **VPC Endpoints**: Set up [vpc-endpoints/vpc-endpoints.tf](./network-security/vpc-endpoints/vpc-endpoints.tf)

#### [IaaS Security](./iaas-security/)
- **Infrastructure**: Deploy [terraform/vpc-private-cluster.tf](./iaas-security/terraform/vpc-private-cluster.tf)
- **Node Hardening**: Run [scripts/deploy-node-security.sh](./iaas-security/scripts/deploy-node-security.sh)
- **Encryption**: Configure [terraform/kms-encryption.tf](./iaas-security/terraform/kms-encryption.tf)
- **Documentation**: Review [shared-responsibility-model.md](./iaas-security/shared-responsibility-model.md)

#### [Monitoring & Compliance](./monitoring-compliance/)
- **CloudWatch**: Deploy [cloudwatch/log-groups.tf](./monitoring-compliance/cloudwatch/log-groups.tf)
- **GuardDuty**: Configure [guardduty/guardduty-eks.tf](./monitoring-compliance/guardduty/guardduty-eks.tf)
- **Compliance**: Run [validation/cis-kubernetes-benchmark.sh](./monitoring-compliance/validation/cis-kubernetes-benchmark.sh)
- **Continuous Monitoring**: Use [validation/continuous-compliance-monitor.sh](./monitoring-compliance/validation/continuous-compliance-monitor.sh)

#### [Validation Framework](./validation-framework/)
- **Comprehensive Testing**: Run [comprehensive-validation.sh](./validation-framework/comprehensive-validation.sh)
- **Incident Response**: Follow [incident-response-procedures.md](./validation-framework/incident-response-procedures.md)
- **Vulnerability Tracking**: Use [vulnerability-mttr-tracking.md](./validation-framework/vulnerability-mttr-tracking.md)
- **Policy Validation**: Execute [admission-policy-validation.md](./validation-framework/admission-policy-validation.md)

## Implementation Guide

### 1. Container Image Security Layer

The foundation of container security begins with secure image construction and vulnerability management.

#### Docker Security Best Practices

**Multi-Stage Build Implementation**:
Multi-stage builds separate build dependencies from runtime dependencies, reducing attack surface by 80-90%.

```dockerfile
# Build stage - includes development tools
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Production stage - minimal runtime environment
FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=builder /app/main /
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/main"]
```

**Security Configuration Locations**:
- **Non-root User**: Dockerfile `USER` directive prevents privilege escalation
- **Read-only Filesystem**: Pod `securityContext.readOnlyRootFilesystem: true`
- **Capability Dropping**: Container `securityContext.capabilities.drop: ["ALL"]`
- **Seccomp Profile**: Pod `securityContext.seccompProfile.type: RuntimeDefault`

#### Vulnerability Scanning Integration

**ECR and Inspector Integration**:
Automated vulnerability scanning with build failure thresholds ensures only secure images reach production.

```yaml
# buildspec.yml - CodeBuild integration
version: 0.2
phases:
  post_build:
    commands:
      - echo Pushing image to ECR...
      - docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/$IMAGE_REPO_NAME:$IMAGE_TAG
      - echo Starting vulnerability scan...
      - aws ecr start-image-scan --repository-name $IMAGE_REPO_NAME --image-id imageTag=$IMAGE_TAG
      - echo Waiting for scan completion...
      - aws ecr wait image-scan-complete --repository-name $IMAGE_REPO_NAME --image-id imageTag=$IMAGE_TAG
      - SCAN_RESULTS=$(aws ecr describe-image-scan-findings --repository-name $IMAGE_REPO_NAME --image-id imageTag=$IMAGE_TAG)
      - CRITICAL_COUNT=$(echo $SCAN_RESULTS | jq '.imageScanFindings.findingCounts.CRITICAL // 0')
      - HIGH_COUNT=$(echo $SCAN_RESULTS | jq '.imageScanFindings.findingCounts.HIGH // 0')
      - |
        if [ $CRITICAL_COUNT -gt 0 ]; then
          echo "Build failed: $CRITICAL_COUNT critical vulnerabilities found"
          exit 1
        elif [ $HIGH_COUNT -gt 5 ]; then
          echo "Build failed: $HIGH_COUNT high vulnerabilities found (threshold: 5)"
          exit 1
        fi
```

### 2. Kubernetes Security Layer

Kubernetes security controls provide runtime protection through admission policies, security contexts, and network isolation.

#### Pod Security Admission

**Restricted Policy Enforcement**:
Pod Security Admission in restricted mode enforces the most stringent security requirements.

```yaml
# Cluster-wide restricted policy
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Security Context Configuration**:
Comprehensive security contexts prevent privilege escalation and limit container capabilities.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: secure-app:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
  volumes:
  - name: tmp-volume
    emptyDir: {}
```

#### Network Security Implementation

**NetworkPolicy Configuration**:
Default-deny network policies with explicit allow rules provide microsegmentation.

```yaml
# Default deny all ingress and egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
# Application-specific policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-app-policy
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: load-balancer
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

### 3. Infrastructure Security Layer

Infrastructure security provides the foundation for container security through VPC design, encryption, and node hardening.

#### Shared Responsibility Model Implementation

**AWS Responsibilities**:
- Physical infrastructure security and hypervisor hardening
- EKS control plane security and managed service availability
- ECR registry infrastructure and base service security

**Customer Responsibilities**:
- VPC design with private subnets and appropriate routing
- EKS node group configuration and AMI selection
- Application-level security and container configuration
- Identity and access management through IRSA

#### VPC and Network Security Design

**Private Cluster Configuration**:
```hcl
# terraform/vpc-private-cluster.tf
resource "aws_eks_cluster" "secure_cluster" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster_role.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    public_access_cidrs     = []
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_encryption.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]
}
```

#### Node Hardening and Patch Management

**SSM Document for Node Hardening**:
```json
{
  "schemaVersion": "2.2",
  "description": "EKS Node Hardening Configuration",
  "parameters": {},
  "mainSteps": [
    {
      "action": "aws:runShellScript",
      "name": "hardenNode",
      "inputs": {
        "runCommand": [
          "#!/bin/bash",
          "# Disable unnecessary services",
          "systemctl disable cups bluetooth",
          "# Configure kernel parameters",
          "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf",
          "echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.conf",
          "sysctl -p",
          "# Update system packages",
          "yum update -y",
          "# Configure audit logging",
          "systemctl enable auditd",
          "systemctl start auditd"
        ]
      }
    }
  ]
}
```

### 4. Identity and Access Management

IRSA (IAM Roles for Service Accounts) provides secure, temporary AWS credentials to pods without storing long-term credentials.

#### IRSA Configuration

**Service Account Setup**:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-access-sa
  namespace: production
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/EKSServiceRole-S3Access
automountServiceAccountToken: true
```

**IAM Role Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE:sub": "system:serviceaccount:production:s3-access-sa",
          "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

### 5. Secrets Management

Secure secrets handling ensures sensitive data is never exposed in container images or logs.

#### Secrets Store CSI Driver Integration

**SecretProviderClass Configuration**:
```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: database-secrets
  namespace: production
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/database/credentials"
        objectType: "secretsmanager"
        jmesPath:
          - path: "username"
            objectAlias: "db_username"
          - path: "password"
            objectAlias: "db_password"
          - path: "host"
            objectAlias: "db_host"
```

**Pod Configuration with Secrets**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: database-app
spec:
  serviceAccountName: database-access-sa
  containers:
  - name: app
    image: database-app:latest
    env:
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          name: database-credentials
          key: db_username
    volumeMounts:
    - name: secrets-store
      mountPath: "/mnt/secrets"
      readOnly: true
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "database-secrets"
```

### 6. Monitoring and Compliance

Comprehensive monitoring provides visibility into security events and compliance status.

#### GuardDuty EKS Protection

**Threat Detection Configuration**:
```bash
# Enable GuardDuty EKS protection
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Enable EKS audit log monitoring
aws guardduty update-detector \
    --detector-id $DETECTOR_ID \
    --features Name=EKS_AUDIT_LOGS,Status=ENABLED
```

#### CloudWatch Container Insights

**Monitoring Stack Deployment**:
```bash
# Deploy CloudWatch Container Insights
curl -s https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluentd-quickstart.yaml | \
sed "s/{{cluster_name}}/$CLUSTER_NAME/;s/{{region_name}}/$AWS_REGION/" | \
kubectl apply -f -
```

## Troubleshooting Guide

### Common Issues and Solutions

#### Image Scanning Failures
**Symptom**: Build pipeline fails during vulnerability scanning
**Solution**: 
1. Check ECR repository permissions
2. Verify Inspector service availability
3. Review vulnerability thresholds in buildspec.yml
4. Update base images to latest security patches

#### IRSA Token Exchange Failures
**Symptom**: Pods cannot access AWS services
**Solution**:
1. Verify OIDC provider configuration: `eksctl utils describe-addon-configuration --cluster $CLUSTER_NAME`
2. Check IAM role trust policy conditions
3. Validate service account annotations
4. Review CloudTrail logs for STS errors

#### Network Policy Violations
**Symptom**: Pod-to-pod communication blocked unexpectedly
**Solution**:
1. Review NetworkPolicy selectors and labels
2. Check CNI plugin compatibility (Calico/Cilium)
3. Validate security group assignments for pods
4. Test connectivity with network debugging tools

#### Secrets Mount Failures
**Symptom**: Pods fail to start with secrets mounting errors
**Solution**:
1. Verify Secrets Store CSI Driver installation
2. Check SecretProviderClass configuration
3. Validate IRSA permissions for Secrets Manager
4. Review secret object names and paths

### Security Incident Response Procedures

#### Container Compromise Response
1. **Immediate Isolation**: Apply network policies to isolate affected pods
2. **Evidence Collection**: Capture pod logs and runtime artifacts
3. **Impact Assessment**: Review GuardDuty findings and CloudTrail logs
4. **Remediation**: Update images, rotate secrets, and redeploy clean workloads
5. **Post-Incident**: Conduct root cause analysis and update security controls

#### Image Vulnerability Response
1. **Vulnerability Assessment**: Review Inspector findings and CVSS scores
2. **Risk Evaluation**: Assess exploitability and business impact
3. **Remediation Planning**: Update base images and rebuild applications
4. **Deployment**: Use blue-green deployment for zero-downtime updates
5. **Validation**: Confirm vulnerability remediation through rescanning

## Security Assumptions and Prerequisites

### Infrastructure Prerequisites
1. **AWS Account Setup**: 
   - Administrative permissions for EKS, ECR, IAM, VPC, KMS, GuardDuty, Config, and CloudTrail
   - Service-linked roles created for EKS, GuardDuty, and Config
   - AWS CLI v2.x configured with appropriate credentials and default region

2. **Network Architecture**:
   - VPC with private subnets for EKS worker nodes
   - NAT Gateway or VPC endpoints for internet connectivity
   - Route 53 private hosted zones for internal DNS resolution
   - Network ACLs and security groups configured for least-privilege access

3. **Encryption and Key Management**:
   - Customer-managed KMS keys for EBS volumes, EFS, and Secrets Manager
   - KMS key policies allowing EKS service and node groups access
   - Envelope encryption enabled for Kubernetes secrets

4. **Monitoring and Logging**:
   - CloudTrail enabled with S3 bucket for audit logs
   - GuardDuty enabled with EKS protection features
   - AWS Config enabled with required configuration rules
   - CloudWatch log groups with appropriate retention policies

### Container Security Prerequisites
1. **Base Image Management**:
   - Approved base image registry (ECR or trusted third-party)
   - Regular base image updates and vulnerability patching schedule
   - Image signing infrastructure (AWS Signer or Cosign)
   - SBOM generation tools (Syft, Grype) integrated in CI/CD

2. **Kubernetes Cluster Requirements**:
   - EKS cluster version 1.24+ with OIDC provider enabled
   - Pod Security Admission enabled in restricted mode
   - RBAC configured with least-privilege service accounts
   - CNI plugin supporting NetworkPolicies (Calico, Cilium, or AWS VPC CNI with Security Groups for Pods)

3. **CI/CD Pipeline Security**:
   - CodeBuild projects with security scanning integration
   - ECR repositories with scan-on-push enabled
   - Build failure thresholds for critical and high vulnerabilities
   - Artifact signing and provenance metadata recording

### Operational Assumptions
1. **Compliance Framework**:
   - SOC 2 Type II, PCI DSS, or industry-specific regulatory requirements
   - Regular security assessments and penetration testing
   - Incident response procedures and escalation paths defined
   - Security training for development and operations teams

2. **Change Management**:
   - All security configuration changes follow approved change control processes
   - Infrastructure as Code (Terraform) for reproducible deployments
   - GitOps workflows for Kubernetes configuration management
   - Automated testing and validation before production deployment

3. **Security Operations**:
   - 24/7 security monitoring and incident response capability
   - Vulnerability management program with defined SLAs
   - Regular security policy reviews and updates
   - Backup and disaster recovery procedures for security configurations

### Deployment Considerations

#### Performance Impact
- **Image Scanning**: Adds 2-5 minutes to build pipeline depending on image size
- **Admission Controllers**: Introduces 100-500ms latency for pod creation
- **Network Policies**: May impact pod-to-pod communication performance by 5-10%
- **Secrets Mounting**: CSI driver adds 10-30 seconds to pod startup time

#### Scalability Considerations
- **ECR Scanning**: Limited to 1000 scans per repository per day
- **GuardDuty**: Processes up to 150GB of data per account per month in free tier
- **KMS**: 5500 requests per second per key for encryption operations
- **Secrets Manager**: 5000 requests per second per secret

#### Cost Implications
- **GuardDuty EKS Protection**: $0.012 per million audit log events
- **ECR Image Scanning**: $0.09 per image scan
- **KMS**: $1 per key per month plus $0.03 per 10,000 requests
- **VPC Endpoints**: $0.01 per hour per endpoint plus data processing charges

#### Regional Availability
- **EKS**: Available in all commercial AWS regions
- **GuardDuty EKS Protection**: Available in most regions (check AWS documentation)
- **ECR Image Scanning**: Available in all regions with ECR
- **AWS Signer**: Limited regional availability (us-east-1, us-west-2, eu-west-1, ap-southeast-1)

### Security Constraints and Limitations

#### Technical Constraints
1. **Pod Security Standards**: Restricted mode may prevent some legacy applications from running
2. **Network Policies**: Require CNI plugin support and may not work with all networking configurations
3. **IRSA**: Limited to 64 IAM roles per service account and requires OIDC provider
4. **Image Signing**: Optional feature that requires additional infrastructure and key management

#### Operational Constraints
1. **Emergency Procedures**: Break-glass access procedures must be defined for security policy bypasses
2. **Compliance Auditing**: All security events must be logged and retained per regulatory requirements
3. **Incident Response**: Security incidents require immediate containment and may impact application availability
4. **Key Rotation**: KMS key rotation requires coordination with application teams and may cause temporary service disruption

## Configuration Reference

### Security Control Locations and Effects

| Security Control | Configuration Location | Security Effect |
|------------------|----------------------|-----------------|
| Non-root User | Dockerfile `USER` directive | Prevents privilege escalation attacks |
| Read-only Filesystem | Pod `securityContext.readOnlyRootFilesystem` | Prevents runtime file modifications |
| Capability Dropping | Container `securityContext.capabilities.drop` | Limits kernel functionality access |
| Seccomp Profile | Pod `securityContext.seccompProfile` | Restricts system call access |
| Network Policies | Kubernetes NetworkPolicy resources | Controls pod-to-pod communication |
| IRSA | Service Account annotations | Provides temporary AWS credentials |
| Secrets Mounting | Secrets Store CSI Driver | Injects secrets without image embedding |
| Image Scanning | ECR Inspector integration | Prevents vulnerable image deployment |
| Node Hardening | SSM documents and scripts | Secures underlying infrastructure |
| Monitoring | CloudWatch and GuardDuty | Detects and responds to threats |

This comprehensive implementation guide provides the foundation for deploying enterprise-grade container security in AWS environments while maintaining operational efficiency and regulatory compliance.
