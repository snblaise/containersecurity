#!/bin/bash

# Admission Policy Validation Script
# This script validates that admission controller policies are working correctly

set -e

# Configuration
NAMESPACE=${TEST_NAMESPACE:-"policy-test"}
SIGNED_IMAGE=${SIGNED_IMAGE:-"123456789012.dkr.ecr.us-east-1.amazonaws.com/signed-app:latest"}
UNSIGNED_IMAGE=${UNSIGNED_IMAGE:-"nginx:latest"}
POLICY_ENGINE=${POLICY_ENGINE:-"kyverno"} # kyverno or gatekeeper

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -n, --namespace NAMESPACE    Test namespace (default: policy-test)"
    echo "  -s, --signed-image IMAGE     Signed image for testing (default: ECR image)"
    echo "  -u, --unsigned-image IMAGE   Unsigned image for testing (default: nginx:latest)"
    echo "  -e, --engine ENGINE          Policy engine (kyverno|gatekeeper, default: kyverno)"
    echo "  -h, --help                   Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  TEST_NAMESPACE               Test namespace"
    echo "  SIGNED_IMAGE                 Signed image for testing"
    echo "  UNSIGNED_IMAGE               Unsigned image for testing"
    echo "  POLICY_ENGINE                Policy engine to test"
    exit 1
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -s|--signed-image)
            SIGNED_IMAGE="$2"
            shift 2
            ;;
        -u|--unsigned-image)
            UNSIGNED_IMAGE="$2"
            shift 2
            ;;
        -e|--engine)
            POLICY_ENGINE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            usage
            ;;
    esac
done

log "Starting admission policy validation"
log "Policy Engine: $POLICY_ENGINE"
log "Test Namespace: $NAMESPACE"
log "Signed Image: $SIGNED_IMAGE"
log "Unsigned Image: $UNSIGNED_IMAGE"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    error "kubectl is not installed or not in PATH"
    exit 1
fi

# Check if policy engine is installed
if [ "$POLICY_ENGINE" = "kyverno" ]; then
    if ! kubectl get crd clusterpolicies.kyverno.io &> /dev/null; then
        error "Kyverno is not installed in the cluster"
        exit 1
    fi
elif [ "$POLICY_ENGINE" = "gatekeeper" ]; then
    if ! kubectl get crd constrainttemplates.templates.gatekeeper.sh &> /dev/null; then
        error "Gatekeeper is not installed in the cluster"
        exit 1
    fi
else
    error "Unsupported policy engine: $POLICY_ENGINE"
    exit 1
fi

# Create test namespace
log "Creating test namespace: $NAMESPACE"
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Test 1: Deploy unsigned image (should be blocked)
log "Test 1: Deploying unsigned image (should be blocked)"
cat > /tmp/unsigned-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: unsigned-test-pod
  namespace: $NAMESPACE
spec:
  containers:
  - name: test-container
    image: $UNSIGNED_IMAGE
    command: ["sleep", "3600"]
EOF

if kubectl apply -f /tmp/unsigned-pod.yaml 2>/dev/null; then
    error "Test 1 FAILED: Unsigned image was allowed"
    TEST1_RESULT="FAIL"
else
    log "Test 1 PASSED: Unsigned image was blocked"
    TEST1_RESULT="PASS"
fi

# Test 2: Deploy signed image with proper annotations (should be allowed)
log "Test 2: Deploying signed image with annotations (should be allowed)"
cat > /tmp/signed-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: signed-test-pod
  namespace: $NAMESPACE
  annotations:
    image.signature.verified: "true"
    sbom.attestation.verified: "true"
    vulnerability.scan.status: "passed"
    vulnerability.scan.critical: "0"
    vulnerability.scan.high: "2"
    provenance.verified: "true"
    provenance.builder: "AWS CodeBuild"
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
  containers:
  - name: test-container
    image: $SIGNED_IMAGE
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
EOF

if kubectl apply -f /tmp/signed-pod.yaml; then
    log "Test 2 PASSED: Signed image with annotations was allowed"
    TEST2_RESULT="PASS"
    
    # Wait for pod to be ready
    kubectl wait --for=condition=Ready pod/signed-test-pod -n "$NAMESPACE" --timeout=60s || true
else
    error "Test 2 FAILED: Signed image with annotations was blocked"
    TEST2_RESULT="FAIL"
fi

# Test 3: Deploy image with high vulnerability count (should be blocked)
log "Test 3: Deploying image with high vulnerability count (should be blocked)"
cat > /tmp/vulnerable-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-test-pod
  namespace: $NAMESPACE
  annotations:
    image.signature.verified: "true"
    sbom.attestation.verified: "true"
    vulnerability.scan.status: "failed"
    vulnerability.scan.critical: "5"
    vulnerability.scan.high: "20"
    provenance.verified: "true"
    provenance.builder: "AWS CodeBuild"
spec:
  containers:
  - name: test-container
    image: $SIGNED_IMAGE
    command: ["sleep", "3600"]
EOF

if kubectl apply -f /tmp/vulnerable-pod.yaml 2>/dev/null; then
    error "Test 3 FAILED: Vulnerable image was allowed"
    TEST3_RESULT="FAIL"
else
    log "Test 3 PASSED: Vulnerable image was blocked"
    TEST3_RESULT="PASS"
fi

# Test 4: Deploy deployment with mixed images (should be blocked)
log "Test 4: Deploying deployment with mixed images (should be blocked)"
cat > /tmp/mixed-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mixed-test-deployment
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mixed-test
  template:
    metadata:
      labels:
        app: mixed-test
      annotations:
        image.signature.verified: "true"
        sbom.attestation.verified: "true"
        vulnerability.scan.status: "passed"
        vulnerability.scan.critical: "0"
        vulnerability.scan.high: "2"
        provenance.verified: "true"
        provenance.builder: "AWS CodeBuild"
    spec:
      containers:
      - name: signed-container
        image: $SIGNED_IMAGE
        command: ["sleep", "3600"]
      - name: unsigned-container
        image: $UNSIGNED_IMAGE
        command: ["sleep", "3600"]
EOF

if kubectl apply -f /tmp/mixed-deployment.yaml 2>/dev/null; then
    error "Test 4 FAILED: Deployment with unsigned image was allowed"
    TEST4_RESULT="FAIL"
else
    log "Test 4 PASSED: Deployment with unsigned image was blocked"
    TEST4_RESULT="PASS"
fi

# Test 5: Check policy exceptions for system namespaces
log "Test 5: Testing policy exceptions for system namespaces"
cat > /tmp/system-pod.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: system-test-pod
  namespace: kube-system
spec:
  containers:
  - name: test-container
    image: $UNSIGNED_IMAGE
    command: ["sleep", "3600"]
EOF

if kubectl apply -f /tmp/system-pod.yaml --dry-run=server 2>/dev/null; then
    log "Test 5 PASSED: System namespace exception works"
    TEST5_RESULT="PASS"
else
    warn "Test 5 INCONCLUSIVE: System namespace test failed (may be due to other policies)"
    TEST5_RESULT="INCONCLUSIVE"
fi

# Test 6: Verify policy status
log "Test 6: Checking policy status"
if [ "$POLICY_ENGINE" = "kyverno" ]; then
    POLICY_COUNT=$(kubectl get clusterpolicies -o json | jq '.items | length')
    if [ "$POLICY_COUNT" -gt 0 ]; then
        log "Test 6 PASSED: Found $POLICY_COUNT Kyverno policies"
        TEST6_RESULT="PASS"
        
        # List policies
        info "Active Kyverno policies:"
        kubectl get clusterpolicies -o custom-columns=NAME:.metadata.name,READY:.status.ready
    else
        error "Test 6 FAILED: No Kyverno policies found"
        TEST6_RESULT="FAIL"
    fi
elif [ "$POLICY_ENGINE" = "gatekeeper" ]; then
    CONSTRAINT_COUNT=$(kubectl get constraints -A -o json | jq '.items | length')
    if [ "$CONSTRAINT_COUNT" -gt 0 ]; then
        log "Test 6 PASSED: Found $CONSTRAINT_COUNT Gatekeeper constraints"
        TEST6_RESULT="PASS"
        
        # List constraints
        info "Active Gatekeeper constraints:"
        kubectl get constraints -A -o custom-columns=NAME:.metadata.name,KIND:.kind,VIOLATIONS:.status.totalViolations
    else
        error "Test 6 FAILED: No Gatekeeper constraints found"
        TEST6_RESULT="FAIL"
    fi
fi

# Cleanup test resources
log "Cleaning up test resources"
kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
rm -f /tmp/unsigned-pod.yaml /tmp/signed-pod.yaml /tmp/vulnerable-pod.yaml /tmp/mixed-deployment.yaml /tmp/system-pod.yaml

# Generate test report
echo ""
log "=== ADMISSION POLICY VALIDATION REPORT ==="
echo "Policy Engine: $POLICY_ENGINE"
echo "Test Namespace: $NAMESPACE"
echo ""
echo "Test Results:"
echo "  Test 1 (Block unsigned images): $TEST1_RESULT"
echo "  Test 2 (Allow signed images): $TEST2_RESULT"
echo "  Test 3 (Block vulnerable images): $TEST3_RESULT"
echo "  Test 4 (Block mixed deployments): $TEST4_RESULT"
echo "  Test 5 (System namespace exceptions): $TEST5_RESULT"
echo "  Test 6 (Policy status check): $TEST6_RESULT"
echo ""

# Calculate overall result
PASS_COUNT=0
FAIL_COUNT=0
for result in "$TEST1_RESULT" "$TEST2_RESULT" "$TEST3_RESULT" "$TEST4_RESULT" "$TEST6_RESULT"; do
    if [ "$result" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "$result" = "FAIL" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

if [ "$FAIL_COUNT" -eq 0 ]; then
    log "Overall Result: PASSED ($PASS_COUNT/5 tests passed)"
    exit 0
else
    error "Overall Result: FAILED ($FAIL_COUNT/5 tests failed)"
    exit 1
fi