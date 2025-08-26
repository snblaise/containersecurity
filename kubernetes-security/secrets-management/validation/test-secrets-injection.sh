#!/bin/bash

# Script to test secrets injection functionality in EKS
# This script validates that secrets are properly mounted and accessible in pods

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-default}"
TEST_TIMEOUT="${TEST_TIMEOUT:-300}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Function to check if required tools are installed
check_dependencies() {
    local missing_tools=()
    
    for tool in kubectl jq; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
}

# Function to set kubectl context if provided
set_kubectl_context() {
    if [ -n "$KUBECTL_CONTEXT" ]; then
        log_info "Setting kubectl context to: $KUBECTL_CONTEXT"
        kubectl config use-context "$KUBECTL_CONTEXT"
    fi
}

# Function to wait for pod to be ready
wait_for_pod_ready() {
    local pod_name="$1"
    local namespace="$2"
    local timeout="$3"
    
    log_info "Waiting for pod $pod_name to be ready (timeout: ${timeout}s)"
    
    if kubectl wait --for=condition=Ready pod/"$pod_name" -n "$namespace" --timeout="${timeout}s" >/dev/null 2>&1; then
        log_info "Pod $pod_name is ready"
        return 0
    else
        log_error "Pod $pod_name failed to become ready within ${timeout}s"
        return 1
    fi
}

# Function to test secrets mounting in pod
test_secrets_mounting() {
    local pod_name="$1"
    local namespace="$2"
    local expected_mounts=("$@")
    local test_results=()
    
    log_info "Testing secrets mounting in pod: $pod_name"
    
    # Remove pod_name and namespace from expected_mounts array
    expected_mounts=("${expected_mounts[@]:2}")
    
    for mount_path in "${expected_mounts[@]}"; do
        log_debug "Checking mount path: $mount_path"
        
        # Check if mount path exists
        if kubectl exec -n "$namespace" "$pod_name" -- test -d "$mount_path" 2>/dev/null; then
            log_info "✅ Mount path exists: $mount_path"
            
            # List files in mount path
            local files
            files=$(kubectl exec -n "$namespace" "$pod_name" -- ls -la "$mount_path" 2>/dev/null || echo "")
            
            if [ -n "$files" ]; then
                log_debug "Files in $mount_path:"
                echo "$files" | while IFS= read -r line; do
                    log_debug "  $line"
                done
                test_results+=("PASS:$mount_path")
            else
                log_warn "⚠️  Mount path is empty: $mount_path"
                test_results+=("WARN:$mount_path:empty")
            fi
        else
            log_error "❌ Mount path does not exist: $mount_path"
            test_results+=("FAIL:$mount_path:not_found")
        fi
    done
    
    echo "${test_results[@]}"
}

# Function to test environment variable injection
test_env_var_injection() {
    local pod_name="$1"
    local namespace="$2"
    local expected_env_vars=("$@")
    local test_results=()
    
    log_info "Testing environment variable injection in pod: $pod_name"
    
    # Remove pod_name and namespace from expected_env_vars array
    expected_env_vars=("${expected_env_vars[@]:2}")
    
    for env_var in "${expected_env_vars[@]}"; do
        log_debug "Checking environment variable: $env_var"
        
        # Check if environment variable exists (without revealing value)
        if kubectl exec -n "$namespace" "$pod_name" -- sh -c "[ -n \"\${$env_var:-}\" ]" 2>/dev/null; then
            log_info "✅ Environment variable exists: $env_var"
            
            # Check if value is not empty
            local value_length
            value_length=$(kubectl exec -n "$namespace" "$pod_name" -- sh -c "echo \${#$env_var}" 2>/dev/null || echo "0")
            
            if [ "$value_length" -gt 0 ]; then
                log_info "✅ Environment variable has value: $env_var (length: $value_length)"
                test_results+=("PASS:$env_var")
            else
                log_warn "⚠️  Environment variable is empty: $env_var"
                test_results+=("WARN:$env_var:empty")
            fi
        else
            log_error "❌ Environment variable not found: $env_var"
            test_results+=("FAIL:$env_var:not_found")
        fi
    done
    
    echo "${test_results[@]}"
}

# Function to test secrets store CSI driver functionality
test_csi_driver_functionality() {
    local pod_name="$1"
    local namespace="$2"
    
    log_info "Testing Secrets Store CSI driver functionality"
    
    # Check if CSI volumes are mounted
    local csi_mounts
    csi_mounts=$(kubectl exec -n "$namespace" "$pod_name" -- mount | grep "secrets-store.csi.k8s.io" || echo "")
    
    if [ -n "$csi_mounts" ]; then
        log_info "✅ Secrets Store CSI volumes are mounted:"
        echo "$csi_mounts" | while IFS= read -r line; do
            log_info "  $line"
        done
        return 0
    else
        log_error "❌ No Secrets Store CSI volumes found"
        return 1
    fi
}

# Function to test IRSA functionality
test_irsa_functionality() {
    local pod_name="$1"
    local namespace="$2"
    
    log_info "Testing IRSA (IAM Roles for Service Accounts) functionality"
    
    # Check if AWS_ROLE_ARN environment variable is set
    local role_arn
    role_arn=$(kubectl exec -n "$namespace" "$pod_name" -- printenv AWS_ROLE_ARN 2>/dev/null || echo "")
    
    if [ -n "$role_arn" ]; then
        log_info "✅ AWS_ROLE_ARN is set: $role_arn"
        
        # Check if AWS_WEB_IDENTITY_TOKEN_FILE exists
        local token_file
        token_file=$(kubectl exec -n "$namespace" "$pod_name" -- printenv AWS_WEB_IDENTITY_TOKEN_FILE 2>/dev/null || echo "")
        
        if [ -n "$token_file" ]; then
            log_info "✅ AWS_WEB_IDENTITY_TOKEN_FILE is set: $token_file"
            
            # Check if token file exists
            if kubectl exec -n "$namespace" "$pod_name" -- test -f "$token_file" 2>/dev/null; then
                log_info "✅ Web identity token file exists"
                return 0
            else
                log_error "❌ Web identity token file does not exist: $token_file"
                return 1
            fi
        else
            log_error "❌ AWS_WEB_IDENTITY_TOKEN_FILE not set"
            return 1
        fi
    else
        log_error "❌ AWS_ROLE_ARN not set"
        return 1
    fi
}

# Function to run comprehensive test suite
run_test_suite() {
    local test_config="$1"
    local results=()
    
    log_info "Running comprehensive secrets injection test suite"
    
    # Parse test configuration
    local pod_name=$(echo "$test_config" | jq -r '.pod_name')
    local namespace=$(echo "$test_config" | jq -r '.namespace')
    local expected_mounts=($(echo "$test_config" | jq -r '.expected_mounts[]'))
    local expected_env_vars=($(echo "$test_config" | jq -r '.expected_env_vars[]'))
    
    log_info "Test configuration:"
    log_info "  Pod: $pod_name"
    log_info "  Namespace: $namespace"
    log_info "  Expected mounts: ${expected_mounts[*]}"
    log_info "  Expected env vars: ${expected_env_vars[*]}"
    
    # Wait for pod to be ready
    if ! wait_for_pod_ready "$pod_name" "$namespace" "$TEST_TIMEOUT"; then
        log_error "Pod readiness test failed"
        return 1
    fi
    
    # Test secrets mounting
    local mount_results
    mount_results=($(test_secrets_mounting "$pod_name" "$namespace" "${expected_mounts[@]}"))
    results+=("${mount_results[@]}")
    
    # Test environment variable injection
    local env_results
    env_results=($(test_env_var_injection "$pod_name" "$namespace" "${expected_env_vars[@]}"))
    results+=("${env_results[@]}")
    
    # Test CSI driver functionality
    if test_csi_driver_functionality "$pod_name" "$namespace"; then
        results+=("PASS:csi_driver")
    else
        results+=("FAIL:csi_driver")
    fi
    
    # Test IRSA functionality
    if test_irsa_functionality "$pod_name" "$namespace"; then
        results+=("PASS:irsa")
    else
        results+=("FAIL:irsa")
    fi
    
    echo "${results[@]}"
}

# Function to generate test report
generate_test_report() {
    local test_results=("$@")
    local total_tests=${#test_results[@]}
    local passed_tests=0
    local failed_tests=0
    local warning_tests=0
    
    # Count results
    for result in "${test_results[@]}"; do
        case "$result" in
            PASS:*)
                ((passed_tests++))
                ;;
            FAIL:*)
                ((failed_tests++))
                ;;
            WARN:*)
                ((warning_tests++))
                ;;
        esac
    done
    
    # Generate report
    cat << EOF
{
  "test_summary": {
    "total_tests": $total_tests,
    "passed": $passed_tests,
    "failed": $failed_tests,
    "warnings": $warning_tests,
    "success_rate": $(echo "scale=2; $passed_tests * 100 / $total_tests" | bc -l 2>/dev/null || echo "0"),
    "overall_status": "$([ $failed_tests -eq 0 ] && echo "PASS" || echo "FAIL")",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "detailed_results": [
$(for result in "${test_results[@]}"; do
    local status=$(echo "$result" | cut -d: -f1)
    local test_name=$(echo "$result" | cut -d: -f2)
    local details=$(echo "$result" | cut -d: -f3-)
    echo "    {\"test\": \"$test_name\", \"status\": \"$status\", \"details\": \"$details\"},"
done | sed '$s/,$//')
  ]
}
EOF
}

# Main execution function
main() {
    local mode="${1:-database-app}"
    
    log_info "Starting secrets injection validation tests"
    log_info "Test mode: $mode"
    
    # Check dependencies
    check_dependencies
    
    # Set kubectl context
    set_kubectl_context
    
    # Define test configurations
    case "$mode" in
        "database-app")
            local test_config='{
                "pod_name": "database-app",
                "namespace": "default",
                "expected_mounts": ["/mnt/secrets", "/mnt/ssl"],
                "expected_env_vars": ["DB_USERNAME", "DB_PASSWORD", "DB_HOST", "DB_PORT"]
            }'
            ;;
        "web-app")
            local test_config='{
                "pod_name": "web-app",
                "namespace": "default",
                "expected_mounts": ["/mnt/secrets", "/mnt/tls", "/mnt/config"],
                "expected_env_vars": ["TLS_CERT_PATH", "TLS_KEY_PATH", "JWT_PRIVATE_KEY_PATH"]
            }'
            ;;
        "monitoring")
            local test_config='{
                "pod_name": "grafana",
                "namespace": "monitoring",
                "expected_mounts": ["/mnt/secrets"],
                "expected_env_vars": ["GF_SECURITY_ADMIN_PASSWORD", "GF_DATABASE_PASSWORD"]
            }'
            ;;
        *)
            log_error "Invalid test mode: $mode"
            log_info "Available modes: database-app, web-app, monitoring"
            exit 1
            ;;
    esac
    
    # Run test suite
    local test_results
    test_results=($(run_test_suite "$test_config"))
    
    # Generate and display report
    local report
    report=$(generate_test_report "${test_results[@]}")
    
    echo ""
    log_info "=== SECRETS INJECTION TEST REPORT ==="
    echo "$report" | jq '.'
    
    # Save report to file
    local report_file="${SCRIPT_DIR}/secrets-injection-test-$(date +%Y%m%d-%H%M%S).json"
    echo "$report" | jq '.' > "$report_file"
    log_info "Detailed report saved to: $report_file"
    
    # Exit with appropriate code
    local overall_status=$(echo "$report" | jq -r '.test_summary.overall_status')
    if [ "$overall_status" = "PASS" ]; then
        log_info "✅ All secrets injection tests passed!"
        exit 0
    else
        log_error "❌ Some secrets injection tests failed!"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"