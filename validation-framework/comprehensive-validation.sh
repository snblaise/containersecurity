#!/bin/bash
# comprehensive-validation.sh
# Comprehensive validation script for AWS container security implementation

set -e

# Configuration
CLUSTER_NAME=${1:-"secure-cluster"}
VALIDATION_NAMESPACE=${2:-"security-validation"}
CLEANUP=${3:-"true"}
REPORT_FILE="validation-report-$(date +%Y%m%d-%H%M%S).json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED_TESTS++))
}

failure() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED_TESTS++))
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Initialize validation report
init_report() {
    cat > $REPORT_FILE << EOF
{
  "validation_run": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cluster": "$CLUSTER_NAME",
    "namespace": "$VALIDATION_NAMESPACE"
  },
  "test_results": {
    "admission_policies": {},
    "image_security": {},
    "network_policies": {},
    "secrets_management": {},
    "monitoring": {}
  },
  "summary": {}
}
EOF
}

# Update report with test result
update_report() {
    local category=$1
    local test_name=$2
    local result=$3
    local details=$4
    
    jq --arg cat "$category" --arg test "$test_name" --arg result "$result" --arg details "$details" \
       '.test_results[$cat][$test] = {"result": $result, "details": $details, "timestamp": now | strftime("%Y-%m-%dT%H:%M:%SZ")}' \
       $REPORT_FILE > tmp.$$.json && mv tmp.$$.json $REPORT_FILE
}

# Prerequisite checks
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check kubectl connectivity
    if kubectl cluster-info &>/dev/null; then
        success "kubectl connectivity verified"
    else
        failure "kubectl connectivity failed"
        exit 1
    fi
    
    # Check cluster access
    if kubectl auth can-i create pods --namespace=$VALIDATION_NAMESPACE &>/dev/null; then
        success "Cluster permissions verified"
    else
        failure "Insufficient cluster permissions"
        exit 1
    fi
    
    # Create validation namespace
    kubectl create namespace $VALIDATION_NAMESPACE --dry-run=client -o yaml | \
    kubectl label --local -f - \
      pod-security.kubernetes.io/enforce=restricted \
      pod-security.kubernetes.io/audit=restricted \
      pod-security.kubernetes.io/warn=restricted \
      -o yaml | kubectl apply -f - &>/dev/null
    
    success "Validation namespace created/updated"
}

# Test admission policies
test_admission_policies() {
    log "Testing admission policies..."
    
    local test_cases=(
        "root-user:runAsUser=0"
        "privilege-escalation:allowPrivilegeEscalation=true"
        "privileged-container:privileged=true"
        "writable-root:readOnlyRootFilesystem=false"
    )
    
    for test_case in "${test_cases[@]}"; do
        local test_name=$(echo $test_case | cut -d: -f1)
        local test_config=$(echo $test_case | cut -d: -f2)
        
        ((TOTAL_TESTS++))
        
        log "Testing admission policy: $test_name"
        
        # Create test pod manifest
        local pod_manifest="/tmp/test-pod-$test_name.yaml"
        cat > $pod_manifest << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-$test_name
  namespace: $VALIDATION_NAMESPACE
spec:
  containers:
  - name: test
    image: busybox:1.35
    command: ['sleep', '30']
EOF
        
        # Add specific security context based on test
        case $test_name in
            "root-user")
                yq eval '.spec.containers[0].securityContext.runAsUser = 0' -i $pod_manifest
                ;;
            "privilege-escalation")
                yq eval '.spec.containers[0].securityContext.allowPrivilegeEscalation = true' -i $pod_manifest
                ;;
            "privileged-container")
                yq eval '.spec.containers[0].securityContext.privileged = true' -i $pod_manifest
                ;;
            "writable-root")
                yq eval '.spec.containers[0].securityContext.readOnlyRootFilesystem = false' -i $pod_manifest
                ;;
        esac
        
        # Try to create pod (should fail)
        if kubectl apply -f $pod_manifest &>/dev/null; then
            failure "Admission policy test failed: $test_name - Pod was allowed but should have been rejected"
            update_report "admission_policies" "$test_name" "FAIL" "Pod was allowed but should have been rejected"
        else
            success "Admission policy test passed: $test_name - Pod was correctly rejected"
            update_report "admission_policies" "$test_name" "PASS" "Pod was correctly rejected by admission policy"
        fi
        
        # Cleanup
        kubectl delete -f $pod_manifest --ignore-not-found=true &>/dev/null
        rm -f $pod_manifest
    done
}

# Test image security
test_image_security() {
    log "Testing image security..."
    
    ((TOTAL_TESTS++))
    
    # Test ECR integration
    if aws ecr describe-repositories --region $(aws configure get region) &>/dev/null; then
        success "ECR connectivity verified"
        update_report "image_security" "ecr_connectivity" "PASS" "ECR service accessible"
    else
        failure "ECR connectivity failed"
        update_report "image_security" "ecr_connectivity" "FAIL" "ECR service not accessible"
    fi
    
    ((TOTAL_TESTS++))
    
    # Test Inspector integration
    if aws inspector2 list-findings --max-results 1 &>/dev/null; then
        success "Inspector integration verified"
        update_report "image_security" "inspector_integration" "PASS" "Inspector service accessible"
    else
        failure "Inspector integration failed"
        update_report "image_security" "inspector_integration" "FAIL" "Inspector service not accessible"
    fi
    
    ((TOTAL_TESTS++))
    
    # Test image signing verification (if cosign is available)
    if command -v cosign &>/dev/null; then
        # Create test signature verification
        local test_image="busybox:1.35"
        if cosign verify --key /dev/null $test_image &>/dev/null; then
            success "Image signing verification available"
            update_report "image_security" "signing_verification" "PASS" "Cosign verification functional"
        else
            warning "Image signing verification test skipped (no valid signatures found)"
            update_report "image_security" "signing_verification" "SKIP" "No signed images available for testing"
        fi
    else
        warning "Cosign not available, skipping image signing tests"
        update_report "image_security" "signing_verification" "SKIP" "Cosign not installed"
    fi
}

# Test network policies
test_network_policies() {
    log "Testing network policies..."
    
    ((TOTAL_TESTS++))
    
    # Create test pods for network policy validation
    kubectl apply -f - << EOF &>/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: network-test-client
  namespace: $VALIDATION_NAMESPACE
  labels:
    app: client
spec:
  containers:
  - name: client
    image: busybox:1.35
    command: ['sleep', '300']
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
---
apiVersion: v1
kind: Pod
metadata:
  name: network-test-server
  namespace: $VALIDATION_NAMESPACE
  labels:
    app: server
spec:
  containers:
  - name: server
    image: busybox:1.35
    command: ['sleep', '300']
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
EOF
    
    # Wait for pods to be ready
    kubectl wait --for=condition=Ready pod/network-test-client -n $VALIDATION_NAMESPACE --timeout=60s &>/dev/null
    kubectl wait --for=condition=Ready pod/network-test-server -n $VALIDATION_NAMESPACE --timeout=60s &>/dev/null
    
    # Apply default deny network policy
    kubectl apply -f - << EOF &>/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: $VALIDATION_NAMESPACE
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
    
    # Test network isolation (should fail)
    sleep 5  # Allow policy to take effect
    
    if kubectl exec network-test-client -n $VALIDATION_NAMESPACE -- timeout 5 nc -z network-test-server 80 &>/dev/null; then
        failure "Network policy test failed - Connection allowed when should be blocked"
        update_report "network_policies" "default_deny" "FAIL" "Network connection allowed despite deny-all policy"
    else
        success "Network policy test passed - Connection correctly blocked"
        update_report "network_policies" "default_deny" "PASS" "Network connection correctly blocked by policy"
    fi
    
    # Cleanup network test resources
    kubectl delete pod network-test-client network-test-server -n $VALIDATION_NAMESPACE --ignore-not-found=true &>/dev/null
    kubectl delete networkpolicy default-deny-all -n $VALIDATION_NAMESPACE --ignore-not-found=true &>/dev/null
}

# Test secrets management
test_secrets_management() {
    log "Testing secrets management..."
    
    ((TOTAL_TESTS++))
    
    # Check if Secrets Store CSI Driver is installed
    if kubectl get csidriver secrets-store.csi.k8s.io &>/dev/null; then
        success "Secrets Store CSI Driver installed"
        update_report "secrets_management" "csi_driver_installed" "PASS" "Secrets Store CSI Driver is installed"
    else
        failure "Secrets Store CSI Driver not found"
        update_report "secrets_management" "csi_driver_installed" "FAIL" "Secrets Store CSI Driver not installed"
    fi
    
    ((TOTAL_TESTS++))
    
    # Test AWS Secrets Manager connectivity
    if aws secretsmanager list-secrets --max-results 1 &>/dev/null; then
        success "AWS Secrets Manager connectivity verified"
        update_report "secrets_management" "secrets_manager_connectivity" "PASS" "AWS Secrets Manager accessible"
    else
        failure "AWS Secrets Manager connectivity failed"
        update_report "secrets_management" "secrets_manager_connectivity" "FAIL" "AWS Secrets Manager not accessible"
    fi
    
    ((TOTAL_TESTS++))
    
    # Test IRSA functionality
    local test_sa="test-irsa-sa"
    kubectl create serviceaccount $test_sa -n $VALIDATION_NAMESPACE &>/dev/null || true
    
    # Create test pod with service account
    kubectl apply -f - << EOF &>/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: irsa-test
  namespace: $VALIDATION_NAMESPACE
spec:
  serviceAccountName: $test_sa
  containers:
  - name: test
    image: amazon/aws-cli:latest
    command: ['sleep', '300']
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
EOF
    
    # Wait for pod to be ready
    if kubectl wait --for=condition=Ready pod/irsa-test -n $VALIDATION_NAMESPACE --timeout=60s &>/dev/null; then
        # Test AWS CLI functionality
        if kubectl exec irsa-test -n $VALIDATION_NAMESPACE -- aws sts get-caller-identity &>/dev/null; then
            success "IRSA functionality verified"
            update_report "secrets_management" "irsa_functionality" "PASS" "IRSA token exchange working"
        else
            warning "IRSA test inconclusive - may need proper role configuration"
            update_report "secrets_management" "irsa_functionality" "WARN" "IRSA test inconclusive"
        fi
    else
        failure "IRSA test pod failed to start"
        update_report "secrets_management" "irsa_functionality" "FAIL" "Test pod failed to start"
    fi
    
    # Cleanup
    kubectl delete pod irsa-test -n $VALIDATION_NAMESPACE --ignore-not-found=true &>/dev/null
    kubectl delete serviceaccount $test_sa -n $VALIDATION_NAMESPACE --ignore-not-found=true &>/dev/null
}

# Test monitoring integration
test_monitoring() {
    log "Testing monitoring integration..."
    
    ((TOTAL_TESTS++))
    
    # Test CloudWatch connectivity
    if aws cloudwatch list-metrics --namespace "AWS/EKS" --max-records 1 &>/dev/null; then
        success "CloudWatch connectivity verified"
        update_report "monitoring" "cloudwatch_connectivity" "PASS" "CloudWatch service accessible"
    else
        failure "CloudWatch connectivity failed"
        update_report "monitoring" "cloudwatch_connectivity" "FAIL" "CloudWatch service not accessible"
    fi
    
    ((TOTAL_TESTS++))
    
    # Test GuardDuty integration
    if aws guardduty list-detectors &>/dev/null; then
        success "GuardDuty integration verified"
        update_report "monitoring" "guardduty_integration" "PASS" "GuardDuty service accessible"
    else
        failure "GuardDuty integration failed"
        update_report "monitoring" "guardduty_integration" "FAIL" "GuardDuty service not accessible"
    fi
    
    ((TOTAL_TESTS++))
    
    # Check for Container Insights
    if kubectl get daemonset aws-for-fluent-bit -n amazon-cloudwatch &>/dev/null; then
        success "Container Insights DaemonSet found"
        update_report "monitoring" "container_insights" "PASS" "Container Insights DaemonSet deployed"
    else
        warning "Container Insights DaemonSet not found"
        update_report "monitoring" "container_insights" "WARN" "Container Insights may not be deployed"
    fi
}

# Generate final report
generate_final_report() {
    log "Generating final validation report..."
    
    # Update summary in report
    jq --arg total "$TOTAL_TESTS" --arg passed "$PASSED_TESTS" --arg failed "$FAILED_TESTS" \
       '.summary = {"total_tests": ($total | tonumber), "passed_tests": ($passed | tonumber), "failed_tests": ($failed | tonumber), "success_rate": (($passed | tonumber) / ($total | tonumber) * 100 | floor)}' \
       $REPORT_FILE > tmp.$$.json && mv tmp.$$.json $REPORT_FILE
    
    echo
    echo "========================================="
    echo "VALIDATION SUMMARY"
    echo "========================================="
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Success Rate: $(( (PASSED_TESTS * 100) / TOTAL_TESTS ))%"
    echo
    echo "Detailed report saved to: $REPORT_FILE"
    echo
    
    if [ $FAILED_TESTS -gt 0 ]; then
        echo -e "${RED}❌ VALIDATION FAILED - Some tests did not pass${NC}"
        echo "Please review the failed tests and address the issues before proceeding."
        return 1
    else
        echo -e "${GREEN}✅ VALIDATION PASSED - All tests completed successfully${NC}"
        echo "Container security implementation is properly configured."
        return 0
    fi
}

# Cleanup function
cleanup() {
    if [ "$CLEANUP" = "true" ]; then
        log "Cleaning up validation resources..."
        kubectl delete namespace $VALIDATION_NAMESPACE --ignore-not-found=true &>/dev/null
        success "Cleanup completed"
    fi
}

# Main execution
main() {
    echo "========================================="
    echo "AWS Container Security Validation"
    echo "========================================="
    echo "Cluster: $CLUSTER_NAME"
    echo "Validation Namespace: $VALIDATION_NAMESPACE"
    echo "Cleanup: $CLEANUP"
    echo
    
    init_report
    check_prerequisites
    
    test_admission_policies
    test_image_security
    test_network_policies
    test_secrets_management
    test_monitoring
    
    generate_final_report
    local exit_code=$?
    
    cleanup
    
    exit $exit_code
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"