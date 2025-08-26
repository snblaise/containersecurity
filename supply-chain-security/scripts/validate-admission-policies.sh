#!/bin/bash

# Validation script for supply chain security admission policies
# Tests Kyverno and Gatekeeper policies for image provenance and signature verification

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_NAMESPACE="${TEST_NAMESPACE:-supply-chain-test}"
CLEANUP_ON_EXIT="${CLEANUP_ON_EXIT:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Test result functions
test_start() {
    local test_name="$1"
    ((TESTS_RUN++))
    log "Starting test: $test_name"
}

test_pass() {
    local test_name="$1"
    ((TESTS_PASSED++))
    success "✓ PASS: $test_name"
}

test_fail() {
    local test_name="$1"
    local reason="$2"
    ((TESTS_FAILED++))
    error "✗ FAIL: $test_name - $reason"
}

# Cleanup function
cleanup() {
    if [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        log "Cleaning up test resources..."
        kubectl delete namespace "$TEST_NAMESPACE" --ignore-not-found=true 2>/dev/null || true
        kubectl delete -f /tmp/test-*.yaml --ignore-not-found=true 2>/dev/null || true
        rm -f /tmp/test-*.yaml 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Function to create test namespace
setup_test_environment() {
    log "Setting up test environment..."
    
    # Create test namespace
    kubectl create namespace "$TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Label namespace for testing
    kubectl label namespace "$TEST_NAMESPACE" security.policy/test=true --overwrite
    
    success "Test environment ready"
}

# Function to test image registry validation
test_image_registry_validation() {
    local test_name="Image Registry Validation"
    test_start "$test_name"
    
    # Test 1: Valid ECR image should be allowed
    cat > /tmp/test-valid-registry.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-valid-registry
  namespace: $TEST_NAMESPACE
  annotations:
    security.provenance/source-repo: "https://github.com/company/app"
    security.provenance/build-id: "build-12345"
spec:
  containers:
  - name: app
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/test-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
EOF
    
    if kubectl apply -f /tmp/test-valid-registry.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Valid ECR image allowed"
    else
        test_fail "$test_name - Valid ECR image rejected" "ECR image should be allowed"
    fi
    
    # Test 2: Invalid registry should be rejected
    cat > /tmp/test-invalid-registry.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-invalid-registry
  namespace: $TEST_NAMESPACE
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if ! kubectl apply -f /tmp/test-invalid-registry.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Invalid registry rejected"
    else
        test_fail "$test_name - Invalid registry allowed" "Docker Hub image should be rejected"
    fi
}

# Function to test image signature validation
test_image_signature_validation() {
    local test_name="Image Signature Validation"
    test_start "$test_name"
    
    # Test 1: Image without signature should be rejected
    cat > /tmp/test-unsigned-image.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned-image
  namespace: $TEST_NAMESPACE
spec:
  containers:
  - name: app
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/unsigned-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if ! kubectl apply -f /tmp/test-unsigned-image.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Unsigned image rejected"
    else
        test_fail "$test_name - Unsigned image allowed" "Unsigned image should be rejected"
    fi
    
    # Test 2: Image with valid signature should be allowed
    cat > /tmp/test-signed-image.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-signed-image
  namespace: $TEST_NAMESPACE
  annotations:
    cosign.sigstore.dev/signature: "MEUCIQDxyz..."
    cosign.sigstore.dev/certificate: "LS0tLS1CRUdJTi..."
    security.provenance/source-repo: "https://github.com/company/app"
    security.provenance/build-id: "build-12345"
spec:
  containers:
  - name: app
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/signed-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
EOF
    
    if kubectl apply -f /tmp/test-signed-image.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Signed image allowed"
    else
        test_fail "$test_name - Signed image rejected" "Signed image should be allowed"
    fi
}

# Function to test vulnerability scan validation
test_vulnerability_scan_validation() {
    local test_name="Vulnerability Scan Validation"
    test_start "$test_name"
    
    # Test 1: Image without scan results should be rejected
    cat > /tmp/test-unscanned-image.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-unscanned-image
  namespace: $TEST_NAMESPACE
spec:
  containers:
  - name: app
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/unscanned-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if ! kubectl apply -f /tmp/test-unscanned-image.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Unscanned image rejected"
    else
        test_fail "$test_name - Unscanned image allowed" "Unscanned image should be rejected"
    fi
    
    # Test 2: Image with acceptable vulnerability levels should be allowed
    cat > /tmp/test-scanned-image-pass.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-scanned-image-pass
  namespace: $TEST_NAMESPACE
  annotations:
    security.scan/scanner: "trivy"
    security.scan/timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    security.scan/critical: "0"
    security.scan/high: "2"
    security.scan/medium: "5"
    security.provenance/source-repo: "https://github.com/company/app"
    security.provenance/build-id: "build-12345"
spec:
  containers:
  - name: app
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/scanned-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
EOF
    
    if kubectl apply -f /tmp/test-scanned-image-pass.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Scanned image with acceptable vulnerabilities allowed"
    else
        test_fail "$test_name - Scanned image rejected" "Image with acceptable vulnerability levels should be allowed"
    fi
    
    # Test 3: Image with too many critical vulnerabilities should be rejected
    cat > /tmp/test-scanned-image-fail.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-scanned-image-fail
  namespace: $TEST_NAMESPACE
  annotations:
    security.scan/scanner: "trivy"
    security.scan/timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    security.scan/critical: "3"
    security.scan/high: "10"
    security.scan/medium: "25"
spec:
  containers:
  - name: app
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnerable-app:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if ! kubectl apply -f /tmp/test-scanned-image-fail.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Image with excessive vulnerabilities rejected"
    else
        test_fail "$test_name - Vulnerable image allowed" "Image with excessive vulnerabilities should be rejected"
    fi
}

# Function to test emergency override functionality
test_emergency_override() {
    local test_name="Emergency Override"
    test_start "$test_name"
    
    # Test 1: Emergency override with proper annotations should be allowed
    cat > /tmp/test-emergency-override.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-emergency-override
  namespace: $TEST_NAMESPACE
  annotations:
    security.policy/emergency-override: "true"
    security.policy/approver: "security-team-lead@company.com"
    security.policy/justification: "Critical security incident response"
    security.policy/incident-id: "INC-12345"
    security.policy/expiry: "$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)"
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest  # Normally would be rejected
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if kubectl apply -f /tmp/test-emergency-override.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Valid emergency override allowed"
    else
        test_fail "$test_name - Emergency override rejected" "Valid emergency override should be allowed"
    fi
    
    # Test 2: Emergency override without proper approver should be rejected
    cat > /tmp/test-invalid-emergency.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-invalid-emergency
  namespace: $TEST_NAMESPACE
  annotations:
    security.policy/emergency-override: "true"
    security.policy/approver: "unauthorized@company.com"
    security.policy/justification: "Test"
    security.policy/incident-id: "INC-99999"
    security.policy/expiry: "$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)"
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if ! kubectl apply -f /tmp/test-invalid-emergency.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Invalid emergency approver rejected"
    else
        test_fail "$test_name - Invalid emergency override allowed" "Invalid emergency approver should be rejected"
    fi
}

# Function to test policy exemptions
test_policy_exemptions() {
    local test_name="Policy Exemptions"
    test_start "$test_name"
    
    # Test 1: System namespace should be exempt
    cat > /tmp/test-system-exemption.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-system-exemption
  namespace: kube-system
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest  # Normally would be rejected
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if kubectl apply -f /tmp/test-system-exemption.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - System namespace exempt"
    else
        test_fail "$test_name - System namespace not exempt" "System namespace should be exempt from policies"
    fi
    
    # Test 2: Emergency namespace should be exempt
    kubectl create namespace emergency --dry-run=client -o yaml | kubectl apply -f - 2>/dev/null || true
    
    cat > /tmp/test-emergency-namespace.yaml << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-emergency-namespace
  namespace: emergency
spec:
  containers:
  - name: app
    image: docker.io/nginx:latest  # Normally would be rejected
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
EOF
    
    if kubectl apply -f /tmp/test-emergency-namespace.yaml --dry-run=server 2>/dev/null; then
        test_pass "$test_name - Emergency namespace exempt"
    else
        test_fail "$test_name - Emergency namespace not exempt" "Emergency namespace should be exempt from policies"
    fi
}

# Function to check policy installation
check_policy_installation() {
    log "Checking admission policy installation..."
    
    # Check for Kyverno
    if kubectl get clusterpolicy verify-image-provenance 2>/dev/null; then
        success "Kyverno policies found"
        return 0
    fi
    
    # Check for Gatekeeper
    if kubectl get constrainttemplate requireimageprovenance 2>/dev/null; then
        success "Gatekeeper policies found"
        return 0
    fi
    
    warning "No admission policies found. Please install Kyverno or Gatekeeper policies first."
    return 1
}

# Function to generate test report
generate_test_report() {
    log "Generating test report..."
    
    local report_file="/tmp/admission-policy-test-report.md"
    
    cat > "$report_file" << EOF
# Supply Chain Security Admission Policy Test Report

**Test Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Test Environment:** $TEST_NAMESPACE namespace

## Summary

- **Total Tests:** $TESTS_RUN
- **Passed:** $TESTS_PASSED
- **Failed:** $TESTS_FAILED
- **Success Rate:** $(( TESTS_PASSED * 100 / TESTS_RUN ))%

## Test Results

EOF
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo "✅ **All tests passed!**" >> "$report_file"
    else
        echo "❌ **$TESTS_FAILED test(s) failed.**" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## Policy Coverage

The following supply chain security controls were tested:

1. **Image Registry Validation**
   - Ensures only approved container registries are used
   - Blocks images from unauthorized registries

2. **Image Signature Verification**
   - Requires valid digital signatures on container images
   - Validates signature authenticity with trusted keys

3. **Vulnerability Scan Validation**
   - Enforces vulnerability scan requirements
   - Blocks images exceeding vulnerability thresholds

4. **Emergency Override Functionality**
   - Allows controlled exceptions for incident response
   - Validates approver authorization and time limits

5. **Policy Exemptions**
   - System namespaces exempt from strict policies
   - Emergency namespaces for incident response

## Recommendations

EOF
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        cat >> "$report_file" << EOF
- Review failed tests and adjust policy configurations
- Ensure admission controllers are properly configured
- Verify policy exemptions are working as expected
EOF
    else
        cat >> "$report_file" << EOF
- All tests passed - admission policies are working correctly
- Consider running tests regularly to ensure continued compliance
- Monitor policy violations in production environments
EOF
    fi
    
    success "Test report generated: $report_file"
    cat "$report_file"
}

# Main function
main() {
    log "Starting supply chain security admission policy validation..."
    
    # Check prerequisites
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is required but not installed"
        exit 1
    fi
    
    # Check if policies are installed
    if ! check_policy_installation; then
        warning "Continuing with tests anyway..."
    fi
    
    # Setup test environment
    setup_test_environment
    
    # Run tests
    test_image_registry_validation
    test_image_signature_validation
    test_vulnerability_scan_validation
    test_emergency_override
    test_policy_exemptions
    
    # Generate report
    generate_test_report
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        success "All tests passed!"
        exit 0
    else
        error "$TESTS_FAILED test(s) failed"
        exit 1
    fi
}

# Execute main function
main "$@"