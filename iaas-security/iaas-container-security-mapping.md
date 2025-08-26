# IaaS Controls to Container Security Requirements Mapping

## Executive Summary

This document provides a detailed mapping between AWS Infrastructure as a Service (IaaS) controls and container security requirements for regulated financial services environments. Each mapping includes the specific AWS service, configuration requirements, and integration points with container security controls.

## Control Category Mappings

### 1. Compute Security Controls

#### EC2 Instance Security → EKS Node Security
**IaaS Control**: EC2 instance hardening and patch management
**Container Security Requirement**: Secure container runtime environment
**Integration Points**:
- **AMI Selection**: Use Amazon EKS-optimized AMIs with latest security patches
- **Instance Metadata Service**: IMDSv2 enforcement for node security
- **Systems Manager**: Automated patching through SSM Patch Manager
- **Security Groups**: Node-level network access controls

**Configuration Example**:
```yaml
# EKS Node Group with security hardening
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: secure-cluster
nodeGroups:
  - name: secure-nodes
    instanceType: m5.large
    amiFamily: AmazonLinux2
    securityGroups:
      attachIDs: ["sg-0123456789abcdef0"]
    iam:
      withAddonPolicies:
        imageBuilder: true
        autoScaler: true
        ebs: true
        efs: true
        albIngress: true
        cloudWatch: true
    ssh:
      enableSsm: true
    preBootstrapCommands:
      - "yum update -y"
      - "echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.conf"
```

#### Auto Scaling → Pod Scaling Security
**IaaS Control**: EC2 Auto Scaling for capacity management
**Container Security Requirement**: Secure scaling without privilege escalation
**Integration Points**:
- **Cluster Autoscaler**: IRSA-based permissions for node scaling
- **Horizontal Pod Autoscaler**: Resource-based scaling with security contexts
- **Vertical Pod Autoscaler**: Memory/CPU limits enforcement

### 2. Network Security Controls

#### VPC Security → Container Network Isolation
**IaaS Control**: Virtual Private Cloud network isolation
**Container Security Requirement**: Pod-to-pod and service-to-service network security
**Integration Points**:
- **Subnet Design**: Private subnets for worker nodes, public for load balancers
- **Route Tables**: Controlled routing for container traffic
- **VPC Endpoints**: Private connectivity to AWS services
- **DNS Resolution**: Private DNS for service discovery

**VPC Configuration**:
```json
{
  "VpcConfig": {
    "SubnetIds": [
      "subnet-private-1a",
      "subnet-private-1b", 
      "subnet-private-1c"
    ],
    "SecurityGroupIds": ["sg-eks-cluster"],
    "EndpointConfigType": "PRIVATE",
    "PublicAccessCidrs": [],
    "PrivateEndpointAccess": true,
    "PublicEndpointAccess": false
  }
}
```

#### Security Groups → Pod Network Policies
**IaaS Control**: EC2 Security Groups for network access control
**Container Security Requirement**: Fine-grained pod network access control
**Integration Points**:
- **Security Groups for Pods**: Direct security group assignment to pods
- **CNI Integration**: VPC CNI plugin for security group enforcement
- **NetworkPolicy Translation**: Kubernetes NetworkPolicies to security group rules

**Security Group for Pods Example**:
```yaml
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: database-pod-security-group
spec:
  podSelector:
    matchLabels:
      app: database
  securityGroups:
    groupIds:
      - sg-database-pods
```

### 3. Identity and Access Management Controls

#### IAM Roles → Pod Identity
**IaaS Control**: IAM roles and policies for AWS service access
**Container Security Requirement**: Pod-level AWS permissions without shared credentials
**Integration Points**:
- **IRSA Configuration**: OIDC provider integration with EKS
- **Service Account Mapping**: Kubernetes service accounts to IAM roles
- **Token Exchange**: STS AssumeRoleWithWebIdentity for temporary credentials

**IRSA Implementation**:
```yaml
# Service Account with IRSA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-access-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/S3AccessRole
automountServiceAccountToken: true
---
# IAM Role Trust Policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.region.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.region.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub": "system:serviceaccount:default:s3-access-sa",
          "oidc.eks.region.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

#### Resource-Based Policies → Container Resource Access
**IaaS Control**: S3 bucket policies, KMS key policies, Secrets Manager resource policies
**Container Security Requirement**: Controlled access to AWS resources from containers
**Integration Points**:
- **Cross-Account Access**: Resource policies for multi-account container deployments
- **Condition-Based Access**: Resource policies with EKS cluster and namespace conditions
- **Audit Trail**: CloudTrail integration for resource access logging

### 4. Data Protection Controls

#### KMS Encryption → Container Data Security
**IaaS Control**: AWS Key Management Service for encryption
**Container Security Requirement**: Encryption of secrets, persistent volumes, and data in transit
**Integration Points**:
- **EKS Secrets Encryption**: Envelope encryption for Kubernetes secrets
- **EBS Volume Encryption**: Encrypted persistent volumes for containers
- **Secrets Manager Integration**: KMS-encrypted secrets injection into containers

**KMS Integration Configuration**:
```yaml
# EKS Cluster with KMS encryption
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: encrypted-cluster
secretsEncryption:
  keyARN: arn:aws:kms:region:account:key/key-id
```

#### AWS Secrets Manager → Container Secrets
**IaaS Control**: Centralized secrets management with automatic rotation
**Container Security Requirement**: Secure secrets injection without embedding in images
**Integration Points**:
- **CSI Driver**: Secrets Store CSI Driver for volume-based secret mounting
- **IRSA Permissions**: Service account permissions for secrets access
- **Automatic Rotation**: Container restart triggers for rotated secrets

### 5. Monitoring and Logging Controls

#### CloudTrail → Container Audit Logging
**IaaS Control**: API call logging and audit trail
**Container Security Requirement**: Comprehensive audit trail for container operations
**Integration Points**:
- **EKS API Logging**: Kubernetes API server audit logs
- **ECR Access Logging**: Container image pull and push operations
- **Cross-Service Correlation**: Unified audit trail across AWS services

#### GuardDuty → Container Threat Detection
**IaaS Control**: Intelligent threat detection service
**Container Security Requirement**: Runtime threat detection for containerized workloads
**Integration Points**:
- **EKS Protection**: GuardDuty EKS protection for cluster-level threats
- **Runtime Monitoring**: Integration with container runtime security tools
- **Automated Response**: Lambda-based automated incident response

**GuardDuty EKS Configuration**:
```json
{
  "DetectorId": "detector-id",
  "Features": [
    {
      "Name": "EKS_AUDIT_LOGS",
      "Status": "ENABLED"
    },
    {
      "Name": "EKS_RUNTIME_MONITORING", 
      "Status": "ENABLED",
      "AdditionalConfiguration": [
        {
          "Name": "EKS_ADDON_MANAGEMENT",
          "Status": "ENABLED"
        }
      ]
    }
  ]
}
```

## Implementation Priority Matrix

### High Priority (Immediate Implementation)
1. **VPC and Network Security**: Private subnets, security groups, VPC endpoints
2. **IRSA Configuration**: Pod-level AWS permissions without shared credentials
3. **KMS Encryption**: Secrets and persistent volume encryption
4. **Basic Monitoring**: CloudTrail and CloudWatch logging

### Medium Priority (Phase 2 Implementation)
1. **Security Groups for Pods**: Fine-grained pod network controls
2. **Advanced GuardDuty**: EKS-specific threat detection
3. **Secrets Manager Integration**: CSI driver and automatic rotation
4. **Network Firewall**: Egress traffic filtering

### Low Priority (Future Enhancement)
1. **Cross-Account Integration**: Multi-account container deployments
2. **Advanced Monitoring**: Custom metrics and alerting
3. **Compliance Automation**: Config rules and remediation
4. **Disaster Recovery**: Cross-region container security

## Validation and Testing

### Infrastructure Validation
- **Network Connectivity**: Verify private subnet routing and VPC endpoint access
- **IAM Permissions**: Test IRSA token exchange and AWS service access
- **Encryption**: Validate KMS key usage and encryption at rest
- **Monitoring**: Confirm log delivery and threat detection alerts

### Container Security Validation
- **Pod Security**: Verify security context enforcement and admission policies
- **Network Policies**: Test pod-to-pod communication restrictions
- **Secrets Access**: Validate secure secrets injection and rotation
- **Image Security**: Confirm vulnerability scanning and admission control

### Integration Testing
- **End-to-End Workflows**: Test complete deployment pipelines with security controls
- **Failure Scenarios**: Validate security control behavior during failures
- **Performance Impact**: Measure security control overhead on application performance
- **Compliance Verification**: Automated compliance checking against security baselines

This mapping ensures that all IaaS security controls are properly integrated with container security requirements, providing defense-in-depth across the entire stack.