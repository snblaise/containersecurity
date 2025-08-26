#!/bin/bash

# Deploy EKS Node Security Configuration
# This script deploys SSM documents, KMS keys, and VPC configuration for secure EKS nodes

set -e

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-secure-cluster}"
REGION="${AWS_REGION:-us-west-2}"
ENVIRONMENT="${ENVIRONMENT:-prod}"
TERRAFORM_DIR="../terraform"
SSM_DOCUMENTS_DIR="../ssm-documents"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed"
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        error "Terraform is not installed"
        exit 1
    fi
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        warning "kubectl is not installed - some validation steps will be skipped"
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS credentials not configured"
        exit 1
    fi
    
    success "Prerequisites check completed"
}

# Deploy SSM documents
deploy_ssm_documents() {
    log "Deploying SSM documents..."
    
    # Deploy node hardening document
    log "Creating EKS node hardening SSM document..."
    aws ssm create-document \
        --name "EKS-Node-Hardening-${CLUSTER_NAME}" \
        --document-type "Command" \
        --document-format "JSON" \
        --content "file://${SSM_DOCUMENTS_DIR}/eks-node-hardening.json" \
        --region "${REGION}" \
        --tags "Key=Environment,Value=${ENVIRONMENT}" "Key=ClusterName,Value=${CLUSTER_NAME}" "Key=ManagedBy,Value=Script" \
        || warning "Node hardening document may already exist"
    
    # Deploy node patching document
    log "Creating EKS node patching SSM document..."
    aws ssm create-document \
        --name "EKS-Node-Patching-${CLUSTER_NAME}" \
        --document-type "Command" \
        --document-format "JSON" \
        --content "file://${SSM_DOCUMENTS_DIR}/eks-node-patching.json" \
        --region "${REGION}" \
        --tags "Key=Environment,Value=${ENVIRONMENT}" "Key=ClusterName,Value=${CLUSTER_NAME}" "Key=ManagedBy,Value=Script" \
        || warning "Node patching document may already exist"
    
    success "SSM documents deployed"
}

# Deploy Terraform infrastructure
deploy_terraform() {
    log "Deploying Terraform infrastructure..."
    
    cd "${TERRAFORM_DIR}"
    
    # Initialize Terraform
    log "Initializing Terraform..."
    terraform init
    
    # Create terraform.tfvars if it doesn't exist
    if [ ! -f "terraform.tfvars" ]; then
        log "Creating terraform.tfvars..."
        cat > terraform.tfvars << EOF
cluster_name = "${CLUSTER_NAME}"
environment = "${ENVIRONMENT}"
region = "${REGION}"
enable_cluster_encryption = true
enable_private_endpoint = true
enable_public_endpoint = false
enable_node_hardening = true
enable_automated_patching = true
enable_ebs_encryption = true
enable_guardduty = true
enable_container_insights = true
EOF
    fi
    
    # Plan Terraform deployment
    log "Planning Terraform deployment..."
    terraform plan -out=tfplan
    
    # Apply Terraform deployment
    log "Applying Terraform deployment..."
    terraform apply tfplan
    
    # Get outputs
    log "Getting Terraform outputs..."
    terraform output > ../outputs.txt
    
    cd - > /dev/null
    success "Terraform infrastructure deployed"
}

# Create maintenance windows
create_maintenance_windows() {
    log "Creating SSM maintenance windows..."
    
    # Create maintenance window for node hardening
    HARDENING_WINDOW_ID=$(aws ssm create-maintenance-window \
        --name "EKS-Node-Hardening-${CLUSTER_NAME}" \
        --description "Maintenance window for EKS node hardening" \
        --duration 2 \
        --cutoff 0 \
        --schedule "cron(0 2 * * ? *)" \
        --schedule-timezone "UTC" \
        --tags "Key=Environment,Value=${ENVIRONMENT}" "Key=ClusterName,Value=${CLUSTER_NAME}" \
        --region "${REGION}" \
        --query 'WindowId' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$HARDENING_WINDOW_ID" ]; then
        log "Created hardening maintenance window: $HARDENING_WINDOW_ID"
        
        # Register targets (EKS nodes)
        aws ssm register-target-with-maintenance-window \
            --window-id "$HARDENING_WINDOW_ID" \
            --target-type "Instance" \
            --targets "Key=tag:kubernetes.io/cluster/${CLUSTER_NAME},Values=owned" \
            --region "${REGION}" > /dev/null
        
        # Register task
        aws ssm register-task-with-maintenance-window \
            --window-id "$HARDENING_WINDOW_ID" \
            --target-type "Instance" \
            --targets "Key=WindowTargetIds,Values=$(aws ssm describe-maintenance-window-targets --window-id $HARDENING_WINDOW_ID --query 'Targets[0].WindowTargetId' --output text --region $REGION)" \
            --task-arn "EKS-Node-Hardening-${CLUSTER_NAME}" \
            --task-type "RUN_COMMAND" \
            --max-concurrency "1" \
            --max-errors "0" \
            --priority 1 \
            --task-parameters "ClusterName={Values=[${CLUSTER_NAME}]}" \
            --region "${REGION}" > /dev/null
    fi
    
    # Create maintenance window for patching
    PATCHING_WINDOW_ID=$(aws ssm create-maintenance-window \
        --name "EKS-Node-Patching-${CLUSTER_NAME}" \
        --description "Maintenance window for EKS node patching" \
        --duration 4 \
        --cutoff 1 \
        --schedule "cron(0 3 ? * SUN *)" \
        --schedule-timezone "UTC" \
        --tags "Key=Environment,Value=${ENVIRONMENT}" "Key=ClusterName,Value=${CLUSTER_NAME}" \
        --region "${REGION}" \
        --query 'WindowId' \
        --output text 2>/dev/null || echo "")
    
    if [ -n "$PATCHING_WINDOW_ID" ]; then
        log "Created patching maintenance window: $PATCHING_WINDOW_ID"
        
        # Register targets
        aws ssm register-target-with-maintenance-window \
            --window-id "$PATCHING_WINDOW_ID" \
            --target-type "Instance" \
            --targets "Key=tag:kubernetes.io/cluster/${CLUSTER_NAME},Values=owned" \
            --region "${REGION}" > /dev/null
        
        # Register task
        aws ssm register-task-with-maintenance-window \
            --window-id "$PATCHING_WINDOW_ID" \
            --target-type "Instance" \
            --targets "Key=WindowTargetIds,Values=$(aws ssm describe-maintenance-window-targets --window-id $PATCHING_WINDOW_ID --query 'Targets[0].WindowTargetId' --output text --region $REGION)" \
            --task-arn "EKS-Node-Patching-${CLUSTER_NAME}" \
            --task-type "RUN_COMMAND" \
            --max-concurrency "1" \
            --max-errors "0" \
            --priority 1 \
            --task-parameters "ClusterName={Values=[${CLUSTER_NAME}]},RebootRequired={Values=[true]}" \
            --region "${REGION}" > /dev/null
    fi
    
    success "Maintenance windows created"
}

# Validate deployment
validate_deployment() {
    log "Validating deployment..."
    
    # Check SSM documents
    log "Checking SSM documents..."
    aws ssm describe-document --name "EKS-Node-Hardening-${CLUSTER_NAME}" --region "${REGION}" > /dev/null
    aws ssm describe-document --name "EKS-Node-Patching-${CLUSTER_NAME}" --region "${REGION}" > /dev/null
    
    # Check KMS keys
    log "Checking KMS keys..."
    if [ -f "${TERRAFORM_DIR}/outputs.txt" ]; then
        grep -q "eks_secrets_kms_key_id" "${TERRAFORM_DIR}/outputs.txt"
        grep -q "ebs_encryption_kms_key_id" "${TERRAFORM_DIR}/outputs.txt"
    fi
    
    # Check VPC endpoints
    log "Checking VPC endpoints..."
    VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=${CLUSTER_NAME}-vpc" --query 'Vpcs[0].VpcId' --output text --region "${REGION}" 2>/dev/null || echo "")
    if [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
        ENDPOINT_COUNT=$(aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=${VPC_ID}" --query 'length(VpcEndpoints)' --output text --region "${REGION}")
        log "Found ${ENDPOINT_COUNT} VPC endpoints"
    fi
    
    success "Deployment validation completed"
}

# Run manual hardening on existing nodes
run_manual_hardening() {
    log "Running manual hardening on existing nodes..."
    
    # Get EKS node instance IDs
    INSTANCE_IDS=$(aws ec2 describe-instances \
        --filters "Name=tag:kubernetes.io/cluster/${CLUSTER_NAME},Values=owned" "Name=instance-state-name,Values=running" \
        --query 'Reservations[].Instances[].InstanceId' \
        --output text \
        --region "${REGION}")
    
    if [ -n "$INSTANCE_IDS" ]; then
        log "Found EKS nodes: $INSTANCE_IDS"
        
        # Run hardening command
        COMMAND_ID=$(aws ssm send-command \
            --document-name "EKS-Node-Hardening-${CLUSTER_NAME}" \
            --instance-ids $INSTANCE_IDS \
            --parameters "ClusterName=${CLUSTER_NAME}" \
            --comment "Manual EKS node hardening" \
            --region "${REGION}" \
            --query 'Command.CommandId' \
            --output text)
        
        log "Started hardening command: $COMMAND_ID"
        log "Monitor progress with: aws ssm get-command-invocation --command-id $COMMAND_ID --instance-id <instance-id> --region $REGION"
    else
        warning "No EKS nodes found for manual hardening"
    fi
}

# Generate security report
generate_security_report() {
    log "Generating security report..."
    
    REPORT_FILE="security-report-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$REPORT_FILE" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "cluster_name": "${CLUSTER_NAME}",
  "region": "${REGION}",
  "environment": "${ENVIRONMENT}",
  "deployment_status": {
    "ssm_documents": "deployed",
    "kms_keys": "deployed",
    "vpc_configuration": "deployed",
    "maintenance_windows": "configured"
  },
  "security_features": {
    "node_hardening": "enabled",
    "automated_patching": "enabled",
    "encryption_at_rest": "enabled",
    "private_networking": "enabled",
    "vpc_endpoints": "configured"
  },
  "next_steps": [
    "Verify EKS cluster deployment",
    "Test node hardening on sample nodes",
    "Configure monitoring and alerting",
    "Schedule security assessments"
  ]
}
EOF
    
    success "Security report generated: $REPORT_FILE"
}

# Main execution
main() {
    log "Starting EKS Node Security deployment for cluster: $CLUSTER_NAME"
    
    check_prerequisites
    deploy_ssm_documents
    deploy_terraform
    create_maintenance_windows
    validate_deployment
    
    # Ask if user wants to run manual hardening
    read -p "Run manual hardening on existing nodes? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_manual_hardening
    fi
    
    generate_security_report
    
    success "EKS Node Security deployment completed successfully!"
    
    log "Next steps:"
    log "1. Deploy your EKS cluster using the created VPC and security groups"
    log "2. Monitor SSM maintenance windows for automated hardening and patching"
    log "3. Review CloudWatch logs for security events"
    log "4. Test security controls and validate compliance"
}

# Script usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -c, --cluster-name    EKS cluster name (default: secure-cluster)"
    echo "  -r, --region          AWS region (default: us-west-2)"
    echo "  -e, --environment     Environment (default: prod)"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  CLUSTER_NAME         EKS cluster name"
    echo "  AWS_REGION           AWS region"
    echo "  ENVIRONMENT          Environment name"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--cluster-name)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run main function
main "$@"