# Security Groups for Pods (SGP) Configuration

This directory contains configurations and scripts for implementing Security Groups for Pods on Amazon EKS. SGP enables you to assign EC2 security groups directly to individual pods, providing fine-grained network security controls at the pod level.

## Overview

Security Groups for Pods (SGP) extends the traditional node-level security group model to provide pod-level network security. This allows you to:

- Apply different security group rules to different pods on the same node
- Implement fine-grained network access controls
- Maintain compliance with security policies that require pod-level isolation
- Integrate with existing AWS security group management workflows

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Amazon EKS Cluster                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │    Node 1   │  │    Node 2   │  │    Node 3   │        │
│  │             │  │             │  │             │        │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │        │
│  │ │  Pod A  │ │  │ │  Pod C  │ │  │ │  Pod E  │ │        │
│  │ │   SG1   │ │  │ │   SG3   │ │  │ │   SG1   │ │        │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │        │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │        │
│  │ │  Pod B  │ │  │ │  Pod D  │ │  │ │  Pod F  │ │        │
│  │ │   SG2   │ │  │ │   SG2   │ │  │ │   SG3   │ │        │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    AWS Security Groups                     │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │
│  │   SG1   │  │   SG2   │  │   SG3   │  │ Common  │       │
│  │Frontend │  │Backend  │  │Database │  │ Egress  │       │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **EKS Cluster Version**: 1.17 or later
2. **VPC CNI Version**: 1.7.5 or later (recommended: 1.18.1+)
3. **Instance Types**: Nitro-based instances that support multiple ENIs
4. **IAM Permissions**: Additional permissions for ENI management

### Supported Instance Types

SGP requires instances that support multiple Elastic Network Interfaces (ENIs):
- All current generation instances (M5, C5, R5, etc.)
- Most previous generation instances (M4, C4, R4, etc.)
- **Not supported**: T2 instances (use T3 or later)

## Files in this Directory

### Configuration Files
- `security-group-policies.yaml` - SecurityGroupPolicy resources for different application tiers
- `aws-security-groups.tf` - Terraform configuration for creating AWS security groups
- `variables.tf` - Terraform variables for security group configuration

### Scripts
- `enable-sgp.sh` - Script to enable Security Groups for Pods on an EKS cluster
- `validate-sgp.sh` - Validation script to verify SGP configuration and enforcement

## Quick Start

### 1. Enable Security Groups for Pods

```bash
# Set your cluster name and region
export CLUSTER_NAME="my-eks-cluster"
export REGION="us-east-1"

# Enable SGP on your cluster
./enable-sgp.sh
```

### 2. Create Security Groups

```bash
# Using Terraform
cd kubernetes-security/security-groups-for-pods/
terraform init
terraform plan -var="cluster_name=my-eks-cluster" -var="vpc_name=my-vpc"
terraform apply
```

### 3. Apply SecurityGroupPolicy Resources

```bash
# Update security group IDs in the YAML file
# Replace sg-xxxxxxxxx with actual security group IDs from Terraform output
kubectl apply -f security-group-policies.yaml
```

### 4. Validate Configuration

```bash
# Run validation script
export NAMESPACE="production"
./validate-sgp.sh
```

## Detailed Configuration

### SecurityGroupPolicy Resource

The `SecurityGroupPolicy` custom resource defines which security groups should be applied to pods matching specific selectors:

```yaml
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: frontend-sgp
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
      tier: web
  securityGroups:
    groupIds:
      - sg-frontend-web-12345678
      - sg-common-egress-12345678
```

### Pod Labels

Ensure your pods have the appropriate labels to match the SecurityGroupPolicy selectors:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend-app
  labels:
    app: frontend
    tier: web
spec:
  # ... pod specification
```

## Security Group Design Patterns

### 1. Layered Security Groups

Use multiple security groups per pod for different purposes:
- **Application-specific**: Rules specific to the application tier
- **Common egress**: Shared outbound rules (HTTPS, DNS)
- **Monitoring**: Rules for metrics collection
- **Compliance**: Additional rules for regulatory requirements

### 2. Environment Separation

Create separate security groups for different environments:
```
sg-prod-frontend-web
sg-staging-frontend-web
sg-dev-frontend-web
```

### 3. Microservices Communication

Design security groups to enforce service-to-service communication:
```
Frontend SG → Backend SG → Database SG
     ↓             ↓            ↓
  Port 8080    Port 3000    Port 5432
```

## Monitoring and Troubleshooting

### Check SGP Status

```bash
# List SecurityGroupPolicy resources
kubectl get securitygrouppolicy -A

# Check pod security group assignments
kubectl get pods -o custom-columns="NAME:.metadata.name,SECURITY-GROUPS:.metadata.annotations.vpc\.amazonaws\.com/pod-eni"
```

### VPC Flow Logs

Enable VPC Flow Logs to monitor network traffic:

```bash
aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids vpc-12345678 \
    --traffic-type ALL \
    --log-destination-type cloud-watch-logs \
    --log-group-name /aws/vpc/flowlogs
```

### Common Issues

1. **Pod Stuck in Pending State**
   - Check if instance type supports multiple ENIs
   - Verify sufficient ENI capacity on nodes
   - Check security group limits (5 per ENI)

2. **Security Groups Not Applied**
   - Verify ENABLE_POD_ENI is set to true
   - Check VPC CNI version compatibility
   - Validate SecurityGroupPolicy selector matches pod labels

3. **Network Connectivity Issues**
   - Review security group rules
   - Check for conflicting NetworkPolicies
   - Verify DNS resolution (UDP 53) is allowed

## Performance Considerations

### ENI Limits

Each instance type has limits on:
- Maximum number of ENIs
- Maximum security groups per ENI (5)
- IP addresses per ENI

### Pod Density

SGP may reduce pod density on nodes due to ENI limitations:
- Each pod with SGP requires its own ENI
- Plan node sizing accordingly
- Consider using Fargate for workloads requiring SGP

## Security Best Practices

1. **Principle of Least Privilege**
   - Only allow necessary ports and protocols
   - Use specific CIDR blocks instead of 0.0.0.0/0
   - Regularly audit and remove unused rules

2. **Defense in Depth**
   - Combine SGP with NetworkPolicies
   - Use both ingress and egress rules
   - Implement monitoring and alerting

3. **Compliance**
   - Document security group purposes
   - Implement change management processes
   - Regular security reviews and audits

## Integration with Other AWS Services

### AWS Config

Monitor security group changes:
```json
{
  "ConfigRuleName": "security-group-ssh-check",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "INCOMING_SSH_DISABLED"
  }
}
```

### AWS Security Hub

Integrate with Security Hub for centralized security findings and compliance monitoring.

### GuardDuty

Enable GuardDuty for EKS to detect suspicious network activity and potential threats.

## Cost Considerations

- Additional ENIs incur small hourly charges
- Data processing charges for cross-AZ traffic
- Consider using placement groups for cost optimization

## Migration Strategy

### Phase 1: Preparation
1. Audit current network policies
2. Design security group architecture
3. Test in non-production environment

### Phase 2: Gradual Rollout
1. Enable SGP on cluster
2. Apply to non-critical workloads first
3. Monitor performance and connectivity

### Phase 3: Full Implementation
1. Apply to all workloads
2. Remove redundant NetworkPolicies
3. Implement monitoring and alerting

## Compliance and Governance

SGP supports various compliance frameworks:
- **SOC 2**: Network access controls and monitoring
- **PCI DSS**: Network segmentation for payment processing
- **HIPAA**: Network isolation for healthcare data
- **FedRAMP**: Government security requirements

## Support and Resources

- [AWS Documentation](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
- [VPC CNI GitHub](https://github.com/aws/amazon-vpc-cni-k8s)
- [EKS Best Practices Guide](https://aws.github.io/aws-eks-best-practices/)

For issues and questions, refer to the AWS EKS documentation or open a support case.