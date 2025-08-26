# Network Security Configuration for EKS Container Security

This directory contains Terraform configurations for implementing comprehensive network security controls for Amazon EKS clusters, including network isolation, egress filtering, and secure subnet configurations.

## Overview

The network security implementation provides multiple layers of protection:

- **AWS Network Firewall**: Stateful inspection and filtering of egress traffic
- **VPC Endpoints**: Secure access to AWS services without internet gateway dependency
- **DNS Filtering**: Domain-based access control using Route 53 Resolver DNS Firewall
- **Private Subnets**: Isolated subnets for EKS nodes with no direct internet access
- **Security Groups**: Least-privilege network access controls for different components
- **Network ACLs**: Additional subnet-level network filtering

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        VPC                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  Public Subnet  │  │ Firewall Subnet │  │Private Subnet│ │
│  │   (NAT GW)      │  │  (Net Firewall) │  │ (EKS Nodes)  │ │
│  │                 │  │                 │  │              │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│           │                     │                   │       │
│           │                     │                   │       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  Internet GW    │  │  VPC Endpoints  │  │ Data Subnet  │ │
│  │                 │  │                 │  │ (Database)   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. AWS Network Firewall (`aws-network-firewall/`)

- **firewall-rules.tf**: Stateful rules for egress traffic filtering
- **firewall-policy.tf**: Firewall policy and logging configuration

**Key Features:**
- Blocks unauthorized egress traffic
- Allows only approved domains and services
- Integrates with AWS managed threat intelligence
- Comprehensive logging to CloudWatch

### 2. VPC Endpoints (`vpc-endpoints/`)

- **vpc-endpoints.tf**: Interface and Gateway endpoints for AWS services

**Supported Services:**
- Amazon ECR (API and DKR)
- Amazon S3 (for ECR image layers)
- Amazon EKS
- CloudWatch Logs and Monitoring
- AWS STS (for IRSA)
- AWS Secrets Manager
- AWS KMS

### 3. DNS Filtering (`dns-filtering/`)

- **route53-resolver.tf**: DNS Firewall rules for domain-based access control

**Features:**
- Allowlist for approved domains
- Blocklist for malicious domains
- Default deny for unlisted domains
- Integration with threat intelligence feeds

### 4. VPC and Subnets (`vpc-subnets/`)

- **private-subnets.tf**: Private subnet configurations with Network ACLs
- **route-tables.tf**: Route table configurations for network isolation

**Subnet Types:**
- **Private EKS Node Subnets**: For worker nodes with no direct internet access
- **Firewall Subnets**: For Network Firewall deployment
- **Data Subnets**: Completely isolated subnets for databases
- **Public Subnets**: Minimal public subnets for NAT Gateways only

### 5. Security Groups (`security-groups/`)

- **eks-security-groups.tf**: Least-privilege security groups for all components

**Security Groups:**
- **EKS Control Plane**: Secure API server access
- **EKS Worker Nodes**: Node-to-node and control plane communication
- **EKS Pods**: Pod-to-pod communication with Security Groups for Pods
- **Load Balancer**: Ingress traffic from approved sources
- **Bastion Host**: Optional SSH access for troubleshooting
- **Database**: Isolated database access from pods only

## Configuration

### Required Variables

```hcl
# Basic Configuration
cluster_name = "my-eks-cluster"
environment  = "production"
vpc_id       = "vpc-12345678"
vpc_cidr     = "10.0.0.0/16"

# Subnet Configuration
private_subnet_cidrs = [
  "10.0.1.0/24",
  "10.0.2.0/24",
  "10.0.3.0/24"
]

private_subnet_ids = [
  "subnet-12345678",
  "subnet-87654321",
  "subnet-11223344"
]

# Firewall Configuration (if enabled)
firewall_subnet_cidrs = [
  "10.0.10.0/24",
  "10.0.11.0/24",
  "10.0.12.0/24"
]

# Route Tables
private_route_table_ids = [
  "rtb-12345678",
  "rtb-87654321"
]
```

### Optional Features

```hcl
# Enable Network Firewall
enable_network_firewall = true

# Enable DNS Filtering
enable_dns_filtering = true

# Create isolated data subnets
create_data_subnets = true
data_subnet_cidrs = [
  "10.0.20.0/24",
  "10.0.21.0/24",
  "10.0.22.0/24"
]

# Enable NAT Gateway for internet access
enable_nat_gateway = true
public_subnet_cidrs = [
  "10.0.100.0/24",
  "10.0.101.0/24",
  "10.0.102.0/24"
]

# Enable SSH access via bastion
enable_ssh_access = true
ssh_allowed_cidr_blocks = ["203.0.113.0/24"]
```

## Security Features

### Network Isolation
- Private subnets with no direct internet access
- Separate subnets for different workload types
- Network ACLs for additional subnet-level filtering
- Route table isolation between subnet types

### Egress Control
- AWS Network Firewall for stateful packet inspection
- DNS filtering to block malicious domains
- VPC endpoints to avoid internet routing for AWS services
- Allowlist-based approach for external connectivity

### Access Control
- Security groups with least-privilege principles
- Support for Security Groups for Pods (SGP)
- Separate security groups for different components
- No default allow rules

### Monitoring and Logging
- CloudWatch logging for Network Firewall
- DNS query logging for Route 53 Resolver
- VPC Flow Logs integration
- Security group rule logging

## Deployment

1. **Initialize Terraform:**
   ```bash
   terraform init
   ```

2. **Plan the deployment:**
   ```bash
   terraform plan -var-file="terraform.tfvars"
   ```

3. **Apply the configuration:**
   ```bash
   terraform apply -var-file="terraform.tfvars"
   ```

## Integration with EKS

### Security Groups for Pods
When using Security Groups for Pods, reference the pod security group:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  annotations:
    eks.amazonaws.com/security-groups: sg-pod-security-group-id
spec:
  # Pod specification
```

### Network Policies
Combine with Kubernetes NetworkPolicies for additional pod-level controls:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

## Compliance and Best Practices

### Security Standards
- Implements defense-in-depth networking
- Follows AWS Well-Architected Security Pillar
- Supports compliance frameworks (SOC 2, PCI DSS)
- Enables comprehensive audit logging

### Operational Considerations
- Regular review of firewall rules and allowed domains
- Monitoring of blocked connections and DNS queries
- Automated threat intelligence updates
- Incident response procedures for network security events

## Troubleshooting

### Common Issues

1. **Pod connectivity issues:**
   - Check security group rules
   - Verify VPC endpoint connectivity
   - Review Network Firewall logs

2. **DNS resolution failures:**
   - Check DNS Firewall rules
   - Verify domain allowlists
   - Review Route 53 Resolver logs

3. **Internet connectivity problems:**
   - Verify NAT Gateway configuration
   - Check route table entries
   - Review Network Firewall egress rules

### Monitoring Commands

```bash
# Check Network Firewall logs
aws logs filter-log-events \
  --log-group-name /aws/networkfirewall/my-cluster \
  --start-time $(date -d '1 hour ago' +%s)000

# Check DNS Firewall logs
aws logs filter-log-events \
  --log-group-name /aws/route53resolver/my-cluster-dns-firewall \
  --start-time $(date -d '1 hour ago' +%s)000
```

## Cost Optimization

- Network Firewall charges per hour and per GB processed
- VPC endpoints charge per hour and per GB transferred
- NAT Gateway charges per hour and per GB processed
- Consider traffic patterns when sizing components

## Security Considerations

- Regularly update allowed domain lists
- Monitor for new AWS service endpoints
- Review and rotate security group rules
- Implement automated compliance checking
- Maintain incident response procedures for network security events