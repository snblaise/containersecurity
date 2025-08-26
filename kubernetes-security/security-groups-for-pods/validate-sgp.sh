#!/bin/bash

# Validation script for Security Groups for Pods (SGP) enforcement
# This script validates that SGP policies are properly applied and enforced

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE=${NAMESPACE:-"production"}
CLUSTER_NAME=${CLUSTER_NAME:-""}
REGION=${REGION:-"us-east-1"}

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
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        log_error "jq is not installed or not in PATH"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Check if Security Groups for Pods is enabled
check_sgp_enabled() {
    log_info "Checking if Security Groups for Pods is enabled..."
    
    # Check if VPC CNI supports SGP
    local vpc_cni_version
    vpc_cni_version=$(kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].image}' | cut -d':' -f2)
    
    if [[ -z "$vpc_cni_version" ]]; then
        log_error "Cannot determine VPC CNI version"
        return 1
    fi
    
    log_info "VPC CNI version: $vpc_cni_version"
    
    # Check if ENABLE_POD_ENI is set
    local enable_pod_eni
    enable_pod_eni=$(kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ENABLE_POD_ENI")].value}')
    
    if [[ "$enable_pod_eni" != "true" ]]; then
        log_error "ENABLE_POD_ENI is not set to true in VPC CNI configuration"
        return 1
    fi
    
    log_success "Security Groups for Pods is enabled"
}

# Validate SecurityGroupPolicy resources
validate_sgp_resources() {
    log_info "Validating SecurityGroupPolicy resources..."
    
    local sgp_count
    sgp_count=$(kubectl get securitygrouppolicy -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
    
    if [[ $sgp_count -eq 0 ]]; then
        log_warning "No SecurityGroupPolicy resources found in namespace $NAMESPACE"
        return 1
    fi
    
    log_info "Found $sgp_count SecurityGroupPolicy resources"
    
    # Validate each SGP
    while IFS= read -r sgp_name; do
        log_info "Validating SecurityGroupPolicy: $sgp_name"
        
        # Check if security groups exist in AWS
        local security_groups
        security_groups=$(kubectl get securitygrouppolicy "$sgp_name" -n "$NAMESPACE" -o jsonpath='{.spec.securityGroups.groupIds[*]}')
        
        for sg_id in $security_groups; do
            if aws ec2 describe-security-groups --group-ids "$sg_id" --region "$REGION" &> /dev/null; then
                log_success "Security group $sg_id exists"
            else
                log_error "Security group $sg_id does not exist or is not accessible"
            fi
        done
        
    done < <(kubectl get securitygrouppolicy -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}')
}

# Check pod security group assignments
check_pod_assignments() {
    log_info "Checking pod security group assignments..."
    
    # Get pods with SGP labels
    local pods_with_sgp
    pods_with_sgp=$(kubectl get pods -n "$NAMESPACE" -l "app" -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -z "$pods_with_sgp" ]]; then
        log_warning "No pods found with app labels in namespace $NAMESPACE"
        return 1
    fi
    
    for pod_name in $pods_with_sgp; do
        log_info "Checking pod: $pod_name"
        
        # Check if pod has security group annotation
        local sg_annotation
        sg_annotation=$(kubectl get pod "$pod_name" -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/pod-eni}' 2>/dev/null || echo "")
        
        if [[ -n "$sg_annotation" ]]; then
            log_success "Pod $pod_name has security group assignment"
            
            # Parse and validate security groups
            local assigned_sgs
            assigned_sgs=$(echo "$sg_annotation" | jq -r '.SecurityGroups[]?' 2>/dev/null || echo "")
            
            if [[ -n "$assigned_sgs" ]]; then
                log_info "Assigned security groups: $assigned_sgs"
            else
                log_warning "Could not parse security group assignment for pod $pod_name"
            fi
        else
            log_warning "Pod $pod_name does not have security group assignment"
        fi
    done
}

# Test network connectivity
test_network_connectivity() {
    log_info "Testing network connectivity with security groups..."
    
    # Create test pods if they don't exist
    create_test_pods
    
    # Test allowed connections
    test_allowed_connections
    
    # Test blocked connections
    test_blocked_connections
    
    # Cleanup test pods
    cleanup_test_pods
}

create_test_pods() {
    log_info "Creating test pods..."
    
    # Frontend test pod
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: sgp-test-frontend
  namespace: $NAMESPACE
  labels:
    app: frontend
    tier: web
    test: sgp-validation
spec:
  containers:
  - name: test
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
  restartPolicy: Never
EOF

    # Backend test pod
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: sgp-test-backend
  namespace: $NAMESPACE
  labels:
    app: backend
    tier: api
    test: sgp-validation
spec:
  containers:
  - name: test
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
  restartPolicy: Never
EOF

    # Wait for pods to be ready
    kubectl wait --for=condition=Ready pod/sgp-test-frontend -n "$NAMESPACE" --timeout=60s
    kubectl wait --for=condition=Ready pod/sgp-test-backend -n "$NAMESPACE" --timeout=60s
    
    log_success "Test pods created and ready"
}

test_allowed_connections() {
    log_info "Testing allowed connections..."
    
    # Test frontend to backend (should be allowed)
    local backend_ip
    backend_ip=$(kubectl get pod sgp-test-backend -n "$NAMESPACE" -o jsonpath='{.status.podIP}')
    
    if kubectl exec sgp-test-frontend -n "$NAMESPACE" -- timeout 5 nc -zv "$backend_ip" 3000 &> /dev/null; then
        log_success "Frontend to backend connection allowed (as expected)"
    else
        log_error "Frontend to backend connection blocked (unexpected)"
    fi
    
    # Test DNS resolution (should be allowed)
    if kubectl exec sgp-test-frontend -n "$NAMESPACE" -- timeout 5 nslookup kubernetes.default.svc.cluster.local &> /dev/null; then
        log_success "DNS resolution working (as expected)"
    else
        log_error "DNS resolution blocked (unexpected)"
    fi
}

test_blocked_connections() {
    log_info "Testing blocked connections..."
    
    # Test backend to frontend (should be blocked)
    local frontend_ip
    frontend_ip=$(kubectl get pod sgp-test-frontend -n "$NAMESPACE" -o jsonpath='{.status.podIP}')
    
    if ! kubectl exec sgp-test-backend -n "$NAMESPACE" -- timeout 5 nc -zv "$frontend_ip" 8080 &> /dev/null; then
        log_success "Backend to frontend connection blocked (as expected)"
    else
        log_warning "Backend to frontend connection allowed (may be unexpected)"
    fi
}

cleanup_test_pods() {
    log_info "Cleaning up test pods..."
    
    kubectl delete pod sgp-test-frontend -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete pod sgp-test-backend -n "$NAMESPACE" --ignore-not-found=true
    
    log_success "Test pods cleaned up"
}

# Generate validation report
generate_report() {
    log_info "Generating validation report..."
    
    local report_file="sgp-validation-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "Security Groups for Pods Validation Report"
        echo "=========================================="
        echo "Date: $(date)"
        echo "Cluster: $CLUSTER_NAME"
        echo "Namespace: $NAMESPACE"
        echo "Region: $REGION"
        echo ""
        
        echo "SecurityGroupPolicy Resources:"
        kubectl get securitygrouppolicy -n "$NAMESPACE" -o wide 2>/dev/null || echo "None found"
        echo ""
        
        echo "Pods with Security Group Assignments:"
        kubectl get pods -n "$NAMESPACE" -o custom-columns="NAME:.metadata.name,SECURITY-GROUPS:.metadata.annotations.vpc\.amazonaws\.com/pod-eni" 2>/dev/null || echo "None found"
        echo ""
        
        echo "VPC CNI Configuration:"
        kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="ENABLE_POD_ENI")]}' 2>/dev/null || echo "Not found"
        
    } > "$report_file"
    
    log_success "Validation report saved to: $report_file"
}

# Main execution
main() {
    log_info "Starting Security Groups for Pods validation..."
    
    check_prerequisites
    check_sgp_enabled
    validate_sgp_resources
    check_pod_assignments
    
    if [[ "${SKIP_CONNECTIVITY_TEST:-false}" != "true" ]]; then
        test_network_connectivity
    else
        log_info "Skipping connectivity tests (SKIP_CONNECTIVITY_TEST=true)"
    fi
    
    generate_report
    
    log_success "Security Groups for Pods validation completed"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h          Show this help message"
        echo "  --skip-tests        Skip connectivity tests"
        echo ""
        echo "Environment variables:"
        echo "  NAMESPACE           Kubernetes namespace to validate (default: production)"
        echo "  CLUSTER_NAME        EKS cluster name"
        echo "  REGION              AWS region (default: us-east-1)"
        echo "  SKIP_CONNECTIVITY_TEST  Skip network connectivity tests (default: false)"
        exit 0
        ;;
    --skip-tests)
        export SKIP_CONNECTIVITY_TEST=true
        main
        ;;
    *)
        main
        ;;
esac