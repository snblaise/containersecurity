#!/bin/bash

# Script to enable Security Groups for Pods (SGP) on Amazon EKS
# This script configures the VPC CNI to support pod-level security group assignment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME=${CLUSTER_NAME:-""}
REGION=${REGION:-"us-east-1"}
VPC_CNI_VERSION=${VPC_CNI_VERSION:-"v1.18.1-eksbuild.1"}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [[ -z "$CLUSTER_NAME" ]]; then
        log_error "CLUSTER_NAME environment variable is required"
        exit 1
    fi
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if aws CLI is available
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Get cluster information
get_cluster_info() {
    log_info "Getting cluster information..."
    
    # Get cluster VPC ID
    local vpc_id
    vpc_id=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --query 'cluster.resourcesVpcConfig.vpcId' --output text)
    
    if [[ -z "$vpc_id" || "$vpc_id" == "None" ]]; then
        log_error "Could not retrieve VPC ID for cluster $CLUSTER_NAME"
        exit 1
    fi
    
    export CLUSTER_VPC_ID="$vpc_id"
    log_info "Cluster VPC ID: $CLUSTER_VPC_ID"
    
    # Get cluster security group
    local cluster_sg
    cluster_sg=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' --output text)
    
    export CLUSTER_SECURITY_GROUP="$cluster_sg"
    log_info "Cluster security group: $CLUSTER_SECURITY_GROUP"
}

# Check current VPC CNI configuration
check_current_config() {
    log_info "Checking current VPC CNI configuration..."
    
    # Check if VPC CNI is installed
    if ! kubectl get daemonset aws-node -n kube-system &> /dev/null; then
        log_error "VPC CNI daemonset not found"
        exit 1
    fi
    
    # Check current version
    local current_version
    current_version=$(kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].image}' | cut -d':' -f2)
    log_info "Current VPC CNI version: $current_version"
    
    # Check if ENABLE_POD_ENI is already set
    local enable_pod_eni
    enable_pod_eni=$(kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ENABLE_POD_ENI")].value}' 2>/dev/null || echo "")
    
    if [[ "$enable_pod_eni" == "true" ]]; then
        log_success "ENABLE_POD_ENI is already set to true"
        return 0
    else
        log_info "ENABLE_POD_ENI is not set or is false"
        return 1
    fi
}

# Update VPC CNI configuration
update_vpc_cni() {
    log_info "Updating VPC CNI configuration to enable Security Groups for Pods..."
    
    # Patch the VPC CNI daemonset to enable POD ENI
    kubectl patch daemonset aws-node -n kube-system -p '{
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "aws-node",
                            "env": [
                                {
                                    "name": "ENABLE_POD_ENI",
                                    "value": "true"
                                }
                            ]
                        }
                    ]
                }
            }
        }
    }' --type=merge
    
    log_success "VPC CNI configuration updated"
}

# Wait for VPC CNI pods to restart
wait_for_vpc_cni_restart() {
    log_info "Waiting for VPC CNI pods to restart..."
    
    # Wait for rollout to complete
    kubectl rollout status daemonset/aws-node -n kube-system --timeout=300s
    
    log_success "VPC CNI pods restarted successfully"
}

# Create IAM policy for Security Groups for Pods
create_iam_policy() {
    log_info "Creating IAM policy for Security Groups for Pods..."
    
    local policy_name="AmazonEKS_SGP_Policy"
    local policy_document='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:AttachNetworkInterface",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DetachNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DescribeInstances",
                    "ec2:ModifyNetworkInterfaceAttribute",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses"
                ],
                "Resource": "*"
            }
        ]
    }'
    
    # Check if policy already exists
    if aws iam get-policy --policy-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$policy_name" --region "$REGION" &> /dev/null; then
        log_info "IAM policy $policy_name already exists"
    else
        # Create the policy
        aws iam create-policy \
            --policy-name "$policy_name" \
            --policy-document "$policy_document" \
            --description "Policy for EKS Security Groups for Pods" \
            --region "$REGION"
        
        log_success "IAM policy $policy_name created"
    fi
    
    export SGP_POLICY_ARN="arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/$policy_name"
}

# Attach IAM policy to node group role
attach_policy_to_node_group() {
    log_info "Attaching IAM policy to node group roles..."
    
    # Get node groups for the cluster
    local node_groups
    node_groups=$(aws eks list-nodegroups --cluster-name "$CLUSTER_NAME" --region "$REGION" --query 'nodegroups' --output text)
    
    if [[ -z "$node_groups" ]]; then
        log_warning "No managed node groups found for cluster $CLUSTER_NAME"
        return 0
    fi
    
    for node_group in $node_groups; do
        log_info "Processing node group: $node_group"
        
        # Get node group role ARN
        local role_arn
        role_arn=$(aws eks describe-nodegroup --cluster-name "$CLUSTER_NAME" --nodegroup-name "$node_group" --region "$REGION" --query 'nodegroup.nodeRole' --output text)
        
        if [[ -n "$role_arn" ]]; then
            local role_name
            role_name=$(echo "$role_arn" | cut -d'/' -f2)
            
            # Attach the policy
            if aws iam attach-role-policy --role-name "$role_name" --policy-arn "$SGP_POLICY_ARN" --region "$REGION"; then
                log_success "Policy attached to role $role_name"
            else
                log_error "Failed to attach policy to role $role_name"
            fi
        else
            log_warning "Could not get role ARN for node group $node_group"
        fi
    done
}

# Verify Security Groups for Pods is working
verify_sgp_functionality() {
    log_info "Verifying Security Groups for Pods functionality..."
    
    # Check if ENABLE_POD_ENI is set correctly
    local enable_pod_eni
    enable_pod_eni=$(kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ENABLE_POD_ENI")].value}')
    
    if [[ "$enable_pod_eni" == "true" ]]; then
        log_success "ENABLE_POD_ENI is correctly set to true"
    else
        log_error "ENABLE_POD_ENI is not set correctly"
        return 1
    fi
    
    # Check VPC CNI logs for any errors
    log_info "Checking VPC CNI logs for errors..."
    local vpc_cni_pod
    vpc_cni_pod=$(kubectl get pods -n kube-system -l k8s-app=aws-node --no-headers | head -1 | awk '{print $1}')
    
    if [[ -n "$vpc_cni_pod" ]]; then
        local error_count
        error_count=$(kubectl logs "$vpc_cni_pod" -n kube-system --tail=100 | grep -i error | wc -l)
        
        if [[ $error_count -eq 0 ]]; then
            log_success "No errors found in VPC CNI logs"
        else
            log_warning "Found $error_count error messages in VPC CNI logs"
        fi
    else
        log_warning "Could not find VPC CNI pod to check logs"
    fi
}

# Create sample SecurityGroupPolicy for testing
create_sample_sgp() {
    log_info "Creating sample SecurityGroupPolicy for testing..."
    
    # Create a test security group
    local test_sg_id
    test_sg_id=$(aws ec2 create-security-group \
        --group-name "eks-sgp-test-$(date +%s)" \
        --description "Test security group for EKS Security Groups for Pods" \
        --vpc-id "$CLUSTER_VPC_ID" \
        --region "$REGION" \
        --query 'GroupId' \
        --output text)
    
    if [[ -n "$test_sg_id" ]]; then
        log_success "Created test security group: $test_sg_id"
        
        # Create sample SecurityGroupPolicy
        kubectl apply -f - <<EOF
apiVersion: vpcresources.k8s.aws/v1beta1
kind: SecurityGroupPolicy
metadata:
  name: sgp-test
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: sgp-test
  securityGroups:
    groupIds:
      - $test_sg_id
EOF
        
        log_success "Created sample SecurityGroupPolicy"
        log_info "You can test SGP by creating a pod with label 'app: sgp-test'"
        log_info "To clean up, delete the SecurityGroupPolicy and security group $test_sg_id"
    else
        log_error "Failed to create test security group"
    fi
}

# Main execution
main() {
    log_info "Starting Security Groups for Pods enablement for cluster: $CLUSTER_NAME"
    
    check_prerequisites
    get_cluster_info
    
    if check_current_config; then
        log_info "Security Groups for Pods is already enabled"
    else
        update_vpc_cni
        wait_for_vpc_cni_restart
    fi
    
    create_iam_policy
    attach_policy_to_node_group
    verify_sgp_functionality
    
    if [[ "${CREATE_SAMPLE:-false}" == "true" ]]; then
        create_sample_sgp
    fi
    
    log_success "Security Groups for Pods enablement completed successfully"
    log_info "You can now create SecurityGroupPolicy resources to assign security groups to pods"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h          Show this help message"
        echo "  --create-sample     Create a sample SecurityGroupPolicy for testing"
        echo ""
        echo "Environment variables:"
        echo "  CLUSTER_NAME        EKS cluster name (required)"
        echo "  REGION              AWS region (default: us-east-1)"
        echo "  VPC_CNI_VERSION     VPC CNI version to use (default: v1.18.1-eksbuild.1)"
        echo "  CREATE_SAMPLE       Create sample SGP for testing (default: false)"
        exit 0
        ;;
    --create-sample)
        export CREATE_SAMPLE=true
        main
        ;;
    *)
        main
        ;;
esac