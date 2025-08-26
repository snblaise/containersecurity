#!/bin/bash

# IRSA Setup Script
# This script helps set up IAM Roles for Service Accounts (IRSA) in EKS

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables (set these before running)
CLUSTER_NAME="${CLUSTER_NAME:-}"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
NAMESPACE="${NAMESPACE:-production}"
SERVICE_ACCOUNT_NAME="${SERVICE_ACCOUNT_NAME:-}"
ROLE_NAME="${ROLE_NAME:-}"
POLICY_NAME="${POLICY_NAME:-}"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if required tools are installed
    local missing_tools=()
    
    if ! command -v aws &> /dev/null; then
        missing_tools+=("aws-cli")
    fi
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again"
        exit 1
    fi
    
    # Check if required variables are set
    local missing_vars=()
    
    if [[ -z "$CLUSTER_NAME" ]]; then
        missing_vars+=("CLUSTER_NAME")
    fi
    
    if [[ -z "$AWS_ACCOUNT_ID" ]]; then
        missing_vars+=("AWS_ACCOUNT_ID")
    fi
    
    if [[ -z "$SERVICE_ACCOUNT_NAME" ]]; then
        missing_vars+=("SERVICE_ACCOUNT_NAME")
    fi
    
    if [[ -z "$ROLE_NAME" ]]; then
        missing_vars+=("ROLE_NAME")
    fi
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        log_error "Please set the missing variables and try again"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        exit 1
    fi
    
    # Check kubectl access
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Function to get OIDC issuer URL
get_oidc_issuer() {
    log_step "Getting OIDC issuer URL for cluster $CLUSTER_NAME..."
    
    local oidc_issuer
    oidc_issuer=$(aws eks describe-cluster \
        --name "$CLUSTER_NAME" \
        --region "$AWS_REGION" \
        --query "cluster.identity.oidc.issuer" \
        --output text)
    
    if [[ -z "$oidc_issuer" ]]; then
        log_error "Failed to get OIDC issuer URL"
        exit 1
    fi
    
    # Extract OIDC ID from the issuer URL
    OIDC_ID=$(echo "$oidc_issuer" | sed 's|https://oidc.eks.*.amazonaws.com/id/||')
    
    log_info "OIDC Issuer: $oidc_issuer"
    log_info "OIDC ID: $OIDC_ID"
    
    echo "$oidc_issuer"
}

# Function to check if OIDC provider exists
check_oidc_provider() {
    local oidc_issuer="$1"
    
    log_step "Checking if OIDC identity provider exists..."
    
    local provider_arn="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${oidc_issuer#https://}"
    
    if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$provider_arn" &> /dev/null; then
        log_info "OIDC provider already exists: $provider_arn"
        echo "$provider_arn"
    else
        log_warn "OIDC provider does not exist: $provider_arn"
        log_info "You may need to create it using: eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve"
        echo ""
    fi
}

# Function to create IAM trust policy
create_trust_policy() {
    log_step "Creating IAM trust policy..."
    
    local trust_policy_file="/tmp/trust-policy-${ROLE_NAME}.json"
    
    cat > "$trust_policy_file" << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/oidc.eks.${AWS_REGION}.amazonaws.com/id/${OIDC_ID}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.${AWS_REGION}.amazonaws.com/id/${OIDC_ID}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT_NAME}",
          "oidc.eks.${AWS_REGION}.amazonaws.com/id/${OIDC_ID}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF
    
    log_info "Trust policy created: $trust_policy_file"
    echo "$trust_policy_file"
}

# Function to create IAM role
create_iam_role() {
    local trust_policy_file="$1"
    
    log_step "Creating IAM role: $ROLE_NAME..."
    
    if aws iam get-role --role-name "$ROLE_NAME" &> /dev/null; then
        log_warn "IAM role $ROLE_NAME already exists"
        
        # Update trust policy
        log_info "Updating trust policy for existing role..."
        aws iam update-assume-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-document "file://$trust_policy_file"
    else
        # Create new role
        aws iam create-role \
            --role-name "$ROLE_NAME" \
            --assume-role-policy-document "file://$trust_policy_file" \
            --description "IRSA role for $SERVICE_ACCOUNT_NAME in $NAMESPACE namespace" \
            --tags Key=CreatedBy,Value=irsa-setup-script \
                   Key=ServiceAccount,Value="$SERVICE_ACCOUNT_NAME" \
                   Key=Namespace,Value="$NAMESPACE" \
                   Key=Cluster,Value="$CLUSTER_NAME"
        
        log_info "IAM role $ROLE_NAME created successfully"
    fi
    
    local role_arn="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"
    echo "$role_arn"
}

# Function to attach policy to role
attach_policy_to_role() {
    local policy_arn="$1"
    
    log_step "Attaching policy to role..."
    
    if [[ "$policy_arn" == arn:aws:iam::aws:policy/* ]]; then
        # AWS managed policy
        aws iam attach-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-arn "$policy_arn"
        log_info "AWS managed policy attached: $policy_arn"
    else
        # Customer managed policy
        aws iam attach-role-policy \
            --role-name "$ROLE_NAME" \
            --policy-arn "$policy_arn"
        log_info "Customer managed policy attached: $policy_arn"
    fi
}

# Function to create Kubernetes service account
create_service_account() {
    local role_arn="$1"
    
    log_step "Creating Kubernetes service account..."
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Creating namespace: $NAMESPACE"
        kubectl create namespace "$NAMESPACE"
    fi
    
    # Create service account YAML
    local sa_file="/tmp/service-account-${SERVICE_ACCOUNT_NAME}.yaml"
    
    cat > "$sa_file" << EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $SERVICE_ACCOUNT_NAME
  namespace: $NAMESPACE
  labels:
    app.kubernetes.io/name: $SERVICE_ACCOUNT_NAME
    app.kubernetes.io/component: service-account
    security.aws.com/irsa-enabled: "true"
  annotations:
    eks.amazonaws.com/role-arn: $role_arn
    eks.amazonaws.com/sts-regional-endpoints: "true"
    security.aws.com/description: "IRSA service account created by setup script"
    security.aws.com/created-by: "irsa-setup-script"
automountServiceAccountToken: true
EOF
    
    # Apply service account
    kubectl apply -f "$sa_file"
    
    log_info "Service account created: $SERVICE_ACCOUNT_NAME in namespace $NAMESPACE"
    log_info "Service account YAML: $sa_file"
}

# Function to test IRSA setup
test_irsa_setup() {
    local role_arn="$1"
    
    log_step "Testing IRSA setup..."
    
    # Create test pod
    local test_pod_file="/tmp/test-pod-${SERVICE_ACCOUNT_NAME}.yaml"
    
    cat > "$test_pod_file" << EOF
apiVersion: v1
kind: Pod
metadata:
  name: irsa-test-${SERVICE_ACCOUNT_NAME}
  namespace: $NAMESPACE
  labels:
    app: irsa-test
spec:
  serviceAccountName: $SERVICE_ACCOUNT_NAME
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
  containers:
  - name: aws-cli
    image: amazon/aws-cli:latest
    command: ["/bin/sh", "-c"]
    args:
    - |
      echo "Testing IRSA setup..."
      echo "AWS_ROLE_ARN: \$AWS_ROLE_ARN"
      echo "AWS_WEB_IDENTITY_TOKEN_FILE: \$AWS_WEB_IDENTITY_TOKEN_FILE"
      
      echo "Getting caller identity..."
      aws sts get-caller-identity
      
      echo "IRSA test completed"
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
      runAsNonRoot: true
      runAsUser: 65534
    resources:
      limits:
        memory: "256Mi"
        cpu: "200m"
      requests:
        memory: "128Mi"
        cpu: "100m"
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
  volumes:
  - name: tmp-volume
    emptyDir:
      sizeLimit: "100Mi"
EOF
    
    # Apply test pod
    kubectl apply -f "$test_pod_file"
    
    log_info "Test pod created. Waiting for completion..."
    
    # Wait for pod to complete
    kubectl wait --for=condition=Ready pod/irsa-test-${SERVICE_ACCOUNT_NAME} -n "$NAMESPACE" --timeout=60s || true
    
    # Show pod logs
    log_info "Test pod logs:"
    kubectl logs irsa-test-${SERVICE_ACCOUNT_NAME} -n "$NAMESPACE" || true
    
    # Cleanup test pod
    kubectl delete pod irsa-test-${SERVICE_ACCOUNT_NAME} -n "$NAMESPACE" --ignore-not-found=true
    
    log_info "Test completed. Check the logs above for results."
}

# Function to display summary
display_summary() {
    local role_arn="$1"
    
    log_step "Setup Summary"
    echo ""
    echo "IRSA setup completed successfully!"
    echo ""
    echo "Configuration:"
    echo "  Cluster Name: $CLUSTER_NAME"
    echo "  AWS Region: $AWS_REGION"
    echo "  AWS Account ID: $AWS_ACCOUNT_ID"
    echo "  Namespace: $NAMESPACE"
    echo "  Service Account: $SERVICE_ACCOUNT_NAME"
    echo "  IAM Role: $ROLE_NAME"
    echo "  Role ARN: $role_arn"
    echo ""
    echo "Next steps:"
    echo "1. Attach appropriate IAM policies to the role: $ROLE_NAME"
    echo "2. Use the service account in your pod specifications"
    echo "3. Test your application's AWS access"
    echo ""
    echo "Example pod usage:"
    echo "  spec:"
    echo "    serviceAccountName: $SERVICE_ACCOUNT_NAME"
}

# Main function
main() {
    echo "IRSA Setup Script"
    echo "=================="
    echo ""
    
    check_prerequisites
    
    local oidc_issuer
    oidc_issuer=$(get_oidc_issuer)
    
    check_oidc_provider "$oidc_issuer"
    
    local trust_policy_file
    trust_policy_file=$(create_trust_policy)
    
    local role_arn
    role_arn=$(create_iam_role "$trust_policy_file")
    
    # Attach policy if specified
    if [[ -n "${POLICY_ARN:-}" ]]; then
        attach_policy_to_role "$POLICY_ARN"
    else
        log_warn "No policy specified. Remember to attach appropriate policies to the role."
    fi
    
    create_service_account "$role_arn"
    
    # Run test if requested
    if [[ "${RUN_TEST:-false}" == "true" ]]; then
        test_irsa_setup "$role_arn"
    fi
    
    display_summary "$role_arn"
    
    # Cleanup temporary files
    rm -f "/tmp/trust-policy-${ROLE_NAME}.json"
    rm -f "/tmp/service-account-${SERVICE_ACCOUNT_NAME}.yaml"
    rm -f "/tmp/test-pod-${SERVICE_ACCOUNT_NAME}.yaml"
}

# Usage function
usage() {
    echo "Usage: $0"
    echo ""
    echo "Required environment variables:"
    echo "  CLUSTER_NAME         - EKS cluster name"
    echo "  AWS_ACCOUNT_ID       - AWS account ID"
    echo "  SERVICE_ACCOUNT_NAME - Kubernetes service account name"
    echo "  ROLE_NAME           - IAM role name to create"
    echo ""
    echo "Optional environment variables:"
    echo "  AWS_REGION          - AWS region (default: us-east-1)"
    echo "  NAMESPACE           - Kubernetes namespace (default: production)"
    echo "  POLICY_ARN          - IAM policy ARN to attach to the role"
    echo "  RUN_TEST            - Run test pod after setup (default: false)"
    echo ""
    echo "Example:"
    echo "  export CLUSTER_NAME=my-eks-cluster"
    echo "  export AWS_ACCOUNT_ID=123456789012"
    echo "  export SERVICE_ACCOUNT_NAME=s3-access-sa"
    echo "  export ROLE_NAME=EKS-S3-Access-Role"
    echo "  export POLICY_ARN=arn:aws:iam::123456789012:policy/S3ReadOnlyPolicy"
    echo "  export RUN_TEST=true"
    echo "  $0"
}

# Check if help is requested
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

# Run main function
main "$@"