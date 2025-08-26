#!/bin/bash

# Pod Security Admission Compliance Validation Script
# This script validates that Pod Security Admission policies are properly configured
# and enforced across the cluster

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
KUBECTL_CMD="kubectl"
TEMP_DIR="/tmp/psa-validation"
TEST_NAMESPACE="psa-test-$(date +%s)"

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

# Cleanup function
cleanup() {
    log_info "Cleaning up test resources..."
    $KUBECTL_CMD delete namespace "$TEST_NAMESPACE" --ignore-not-found=true
    rm -rf "$TEMP_DIR"
}

# Set trap for cleanup
trap cleanup EXIT

# Create temporary directory
mkdir -p "$TEMP_DIR"

# Function to check if kubectl is available and cluster is accessible
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! $KUBECTL_CMD cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Function to validate namespace PSA labels
validate_namespace_labels() {
    log_info "Validating namespace Pod Security Admission labels..."
    
    local namespaces=("default" "production" "development")
    local failed=0
    
    for ns in "${namespaces[@]}"; do
        if $KUBECTL_CMD get namespace "$ns" &> /dev/null; then
            local enforce_label=$($KUBECTL_CMD get namespace "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || echo "")
            local audit_label=$($KUBECTL_CMD get namespace "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/audit}' 2>/dev/null || echo "")
            local warn_label=$($KUBECTL_CMD get namespace "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}' 2>/dev/null || echo "")
            
            if [[ -n "$enforce_label" && -n "$audit_label" && -n "$warn_label" ]]; then
                log_info "Namespace '$ns' has PSA labels: enforce=$enforce_label, audit=$audit_label, warn=$warn_label"
            else
                log_error "Namespace '$ns' is missing required PSA labels"
                ((failed++))
            fi
        else
            log_warn "Namespace '$ns' does not exist"
        fi
    done
    
    return $failed
}

# Function to test restricted policy enforcement
test_restricted_policy() {
    log_info "Testing restricted policy enforcement..."
    
    # Create test namespace with restricted policy
    cat > "$TEMP_DIR/test-namespace.yaml" << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $TEST_NAMESPACE
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
EOF
    
    $KUBECTL_CMD apply -f "$TEMP_DIR/test-namespace.yaml"
    
    # Test 1: Try to create a non-compliant pod (should fail)
    log_info "Test 1: Creating non-compliant pod (should be rejected)..."
    cat > "$TEMP_DIR/non-compliant-pod.yaml" << EOF
apiVersion: v1
kind: Pod
metadata:
  name: non-compliant-pod
  namespace: $TEST_NAMESPACE
spec:
  containers:
  - name: test-container
    image: nginx:latest
    # This pod violates restricted policy:
    # - No securityContext
    # - Running as root
    # - Privileged capabilities
EOF
    
    if $KUBECTL_CMD apply -f "$TEMP_DIR/non-compliant-pod.yaml" 2>/dev/null; then
        log_error "Non-compliant pod was allowed (PSA policy not working)"
        return 1
    else
        log_info "Non-compliant pod was correctly rejected"
    fi
    
    # Test 2: Create a compliant pod (should succeed)
    log_info "Test 2: Creating compliant pod (should be accepted)..."
    cat > "$TEMP_DIR/compliant-pod.yaml" << EOF
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
  namespace: $TEST_NAMESPACE
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: test-container
    image: nginx:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: var-cache
      mountPath: /var/cache/nginx
    - name: var-run
      mountPath: /var/run
  volumes:
  - name: tmp
    emptyDir: {}
  - name: var-cache
    emptyDir: {}
  - name: var-run
    emptyDir: {}
EOF
    
    if $KUBECTL_CMD apply -f "$TEMP_DIR/compliant-pod.yaml"; then
        log_info "Compliant pod was correctly accepted"
        
        # Wait for pod to be ready or fail
        log_info "Waiting for pod to be ready..."
        if $KUBECTL_CMD wait --for=condition=Ready pod/compliant-pod -n "$TEST_NAMESPACE" --timeout=60s; then
            log_info "Compliant pod is running successfully"
        else
            log_warn "Compliant pod failed to start (may be due to image/configuration issues)"
        fi
    else
        log_error "Compliant pod was rejected (unexpected)"
        return 1
    fi
    
    return 0
}

# Function to check admission controller configuration
check_admission_controller() {
    log_info "Checking Pod Security Admission controller status..."
    
    # Check if PSA is enabled by looking at API server configuration
    # This is a basic check - in real environments you might need to check the API server flags
    if $KUBECTL_CMD get --raw /api/v1 | grep -q "pod-security"; then
        log_info "Pod Security Admission API is available"
    else
        log_warn "Cannot verify Pod Security Admission API availability"
    fi
    
    # Check for PSA-related events
    local psa_events=$($KUBECTL_CMD get events --all-namespaces --field-selector reason=FailedCreate -o json | jq -r '.items[] | select(.message | contains("pod security")) | .message' 2>/dev/null || echo "")
    
    if [[ -n "$psa_events" ]]; then
        log_info "Found Pod Security Admission events in cluster"
        echo "$psa_events" | head -5
    fi
}

# Function to generate compliance report
generate_report() {
    log_info "Generating compliance report..."
    
    local report_file="$TEMP_DIR/psa-compliance-report.txt"
    
    cat > "$report_file" << EOF
Pod Security Admission Compliance Report
Generated: $(date)
Cluster: $($KUBECTL_CMD config current-context)

=== Namespace Configuration ===
EOF
    
    # List all namespaces with their PSA labels
    $KUBECTL_CMD get namespaces -o custom-columns="NAME:.metadata.name,ENFORCE:.metadata.labels.pod-security\.kubernetes\.io/enforce,AUDIT:.metadata.labels.pod-security\.kubernetes\.io/audit,WARN:.metadata.labels.pod-security\.kubernetes\.io/warn" >> "$report_file"
    
    echo "" >> "$report_file"
    echo "=== Recent PSA Events ===" >> "$report_file"
    $KUBECTL_CMD get events --all-namespaces --field-selector reason=FailedCreate -o custom-columns="NAMESPACE:.namespace,NAME:.involvedObject.name,REASON:.reason,MESSAGE:.message" | grep -i "pod security" | head -10 >> "$report_file" || echo "No recent PSA events found" >> "$report_file"
    
    log_info "Compliance report saved to: $report_file"
    cat "$report_file"
}

# Main execution
main() {
    log_info "Starting Pod Security Admission compliance validation..."
    
    check_prerequisites
    
    local exit_code=0
    
    # Run validation tests
    if ! validate_namespace_labels; then
        log_error "Namespace label validation failed"
        ((exit_code++))
    fi
    
    if ! test_restricted_policy; then
        log_error "Restricted policy testing failed"
        ((exit_code++))
    fi
    
    check_admission_controller
    generate_report
    
    if [[ $exit_code -eq 0 ]]; then
        log_info "All Pod Security Admission compliance tests passed!"
    else
        log_error "Some compliance tests failed. Check the output above for details."
    fi
    
    return $exit_code
}

# Run main function
main "$@"