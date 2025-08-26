#!/bin/bash

# Container Security Policy Compliance Validation Script
# This script validates security policy compliance across EKS clusters
# Requirements: 4.2, 4.5

set -euo pipefail

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-}"
NAMESPACE="${NAMESPACE:-default}"
VERBOSE="${VERBOSE:-false}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-json}"
COMPLIANCE_THRESHOLD="${COMPLIANCE_THRESHOLD:-90}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Container Security Policy Compliance Validation

OPTIONS:
    -c, --cluster CLUSTER_NAME    EKS cluster name (required)
    -n, --namespace NAMESPACE     Kubernetes namespace (default: default)
    -v, --verbose                 Enable verbose output
    -f, --format FORMAT           Output format: json, yaml, table (default: json)
    -t, --threshold THRESHOLD     Compliance threshold percentage (default: 90)
    -h, --help                    Show this help message

EXAMPLES:
    $0 --cluster production-eks --namespace kube-system
    $0 -c staging-eks -f table -v
    CLUSTER_NAME=prod-eks $0 --format yaml

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--cluster)
                CLUSTER_NAME="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -t|--threshold)
                COMPLIANCE_THRESHOLD="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    if [[ -z "$CLUSTER_NAME" ]]; then
        log_error "Cluster name is required"
        usage
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()

    command -v kubectl >/dev/null 2>&1 || missing_tools+=("kubectl")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")
    command -v yq >/dev/null 2>&1 || missing_tools+=("yq")

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again"
        exit 1
    fi

    # Check kubectl context
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        log_error "Please check your kubectl configuration"
        exit 1
    fi

    local current_context
    current_context=$(kubectl config current-context)
    if [[ "$current_context" != *"$CLUSTER_NAME"* ]]; then
        log_warn "Current kubectl context ($current_context) may not match cluster name ($CLUSTER_NAME)"
    fi
}

# Initialize compliance results
init_results() {
    cat > /tmp/compliance_results.json << EOF
{
  "cluster_name": "$CLUSTER_NAME",
  "namespace": "$NAMESPACE",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "compliance_threshold": $COMPLIANCE_THRESHOLD,
  "checks": [],
  "summary": {
    "total_checks": 0,
    "passed_checks": 0,
    "failed_checks": 0,
    "compliance_percentage": 0,
    "overall_status": "UNKNOWN"
  }
}
EOF
}

# Add check result to compliance results
add_check_result() {
    local check_name="$1"
    local status="$2"
    local message="$3"
    local severity="${4:-MEDIUM}"
    local remediation="${5:-}"

    local result
    result=$(jq -n \
        --arg name "$check_name" \
        --arg status "$status" \
        --arg message "$message" \
        --arg severity "$severity" \
        --arg remediation "$remediation" \
        '{
            name: $name,
            status: $status,
            message: $message,
            severity: $severity,
            remediation: $remediation,
            timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")
        }')

    jq --argjson result "$result" '.checks += [$result]' /tmp/compliance_results.json > /tmp/compliance_results_tmp.json
    mv /tmp/compliance_results_tmp.json /tmp/compliance_results.json
}

# Check Pod Security Admission policies
check_pod_security_admission() {
    log_info "Checking Pod Security Admission policies..."

    local psa_enabled=false
    local restricted_namespaces=0
    local total_namespaces=0

    # Check if PSA is enabled at cluster level
    if kubectl get --raw /api/v1/namespaces | jq -r '.items[].metadata.labels["pod-security.kubernetes.io/enforce"]' | grep -q "restricted"; then
        psa_enabled=true
    fi

    # Count namespaces with restricted PSA
    while IFS= read -r namespace; do
        ((total_namespaces++))
        local enforce_level
        enforce_level=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || echo "")
        
        if [[ "$enforce_level" == "restricted" ]]; then
            ((restricted_namespaces++))
        fi
    done < <(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')

    if [[ $psa_enabled == true ]] && [[ $restricted_namespaces -gt 0 ]]; then
        add_check_result "Pod Security Admission" "PASS" "PSA is enabled with $restricted_namespaces/$total_namespaces namespaces using restricted policy" "HIGH"
    else
        add_check_result "Pod Security Admission" "FAIL" "PSA is not properly configured. Only $restricted_namespaces/$total_namespaces namespaces use restricted policy" "HIGH" "Enable Pod Security Admission with restricted policy on all namespaces"
    fi
}

# Check security contexts in pods
check_security_contexts() {
    log_info "Checking security contexts in pods..."

    local pods_with_security_context=0
    local total_pods=0
    local privileged_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        # Check if pod has security context
        local has_security_context
        has_security_context=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.securityContext}' 2>/dev/null || echo "")
        
        if [[ -n "$has_security_context" && "$has_security_context" != "null" ]]; then
            ((pods_with_security_context++))
        fi

        # Check for privileged containers
        local privileged_containers
        privileged_containers=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null || echo "")
        
        if [[ "$privileged_containers" == *"true"* ]]; then
            ((privileged_pods++))
            [[ "$VERBOSE" == true ]] && log_warn "Privileged pod found: $pod_name in namespace $namespace"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    local security_context_percentage=0
    if [[ $total_pods -gt 0 ]]; then
        security_context_percentage=$((pods_with_security_context * 100 / total_pods))
    fi

    if [[ $security_context_percentage -ge $COMPLIANCE_THRESHOLD ]] && [[ $privileged_pods -eq 0 ]]; then
        add_check_result "Security Contexts" "PASS" "$pods_with_security_context/$total_pods pods have security contexts, no privileged pods found" "HIGH"
    else
        add_check_result "Security Contexts" "FAIL" "Only $pods_with_security_context/$total_pods pods have security contexts, $privileged_pods privileged pods found" "HIGH" "Add securityContext to all pod specifications and remove privileged containers"
    fi
}

# Check network policies
check_network_policies() {
    log_info "Checking network policies..."

    local namespaces_with_policies=0
    local total_namespaces=0
    local default_deny_policies=0

    while IFS= read -r namespace; do
        ((total_namespaces++))
        
        local policy_count
        policy_count=$(kubectl get networkpolicies -n "$namespace" --no-headers 2>/dev/null | wc -l)
        
        if [[ $policy_count -gt 0 ]]; then
            ((namespaces_with_policies++))
            
            # Check for default deny policies
            if kubectl get networkpolicies -n "$namespace" -o yaml 2>/dev/null | grep -q "podSelector: {}"; then
                ((default_deny_policies++))
            fi
        fi
    done < <(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')

    local policy_coverage_percentage=0
    if [[ $total_namespaces -gt 0 ]]; then
        policy_coverage_percentage=$((namespaces_with_policies * 100 / total_namespaces))
    fi

    if [[ $policy_coverage_percentage -ge $COMPLIANCE_THRESHOLD ]] && [[ $default_deny_policies -gt 0 ]]; then
        add_check_result "Network Policies" "PASS" "$namespaces_with_policies/$total_namespaces namespaces have network policies, $default_deny_policies default-deny policies found" "MEDIUM"
    else
        add_check_result "Network Policies" "FAIL" "Only $namespaces_with_policies/$total_namespaces namespaces have network policies, $default_deny_policies default-deny policies" "MEDIUM" "Implement network policies for all namespaces with default-deny rules"
    fi
}

# Check RBAC configuration
check_rbac() {
    log_info "Checking RBAC configuration..."

    local cluster_admin_bindings=0
    local service_accounts_with_rbac=0
    local total_service_accounts=0

    # Check for cluster-admin role bindings
    cluster_admin_bindings=$(kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .metadata.name' | wc -l)

    # Check service accounts with RBAC
    while IFS= read -r sa_info; do
        ((total_service_accounts++))
        local sa_name namespace
        sa_name=$(echo "$sa_info" | cut -d' ' -f1)
        namespace=$(echo "$sa_info" | cut -d' ' -f2)

        # Check if service account has role bindings
        local has_rbac
        has_rbac=$(kubectl get rolebindings,clusterrolebindings --all-namespaces -o json | jq -r --arg sa "$sa_name" --arg ns "$namespace" '.items[] | select(.subjects[]? | select(.kind == "ServiceAccount" and .name == $sa and .namespace == $ns)) | .metadata.name' | wc -l)
        
        if [[ $has_rbac -gt 0 ]]; then
            ((service_accounts_with_rbac++))
        fi
    done < <(kubectl get serviceaccounts --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers | grep -v "default")

    if [[ $cluster_admin_bindings -le 2 ]] && [[ $service_accounts_with_rbac -gt 0 ]]; then
        add_check_result "RBAC Configuration" "PASS" "Limited cluster-admin bindings ($cluster_admin_bindings), $service_accounts_with_rbac service accounts have RBAC" "HIGH"
    else
        add_check_result "RBAC Configuration" "FAIL" "Too many cluster-admin bindings ($cluster_admin_bindings) or insufficient RBAC coverage" "HIGH" "Review and minimize cluster-admin role bindings, ensure all service accounts have appropriate RBAC"
    fi
}

# Check image security
check_image_security() {
    log_info "Checking image security..."

    local pods_with_latest_tag=0
    local pods_with_digest=0
    local total_pods=0
    local non_root_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        # Check image tags
        local images
        images=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.containers[*].image}' 2>/dev/null || echo "")
        
        if [[ "$images" == *":latest"* ]]; then
            ((pods_with_latest_tag++))
            [[ "$VERBOSE" == true ]] && log_warn "Pod with :latest tag: $pod_name in namespace $namespace"
        fi

        if [[ "$images" == *"@sha256:"* ]]; then
            ((pods_with_digest++))
        fi

        # Check runAsNonRoot
        local run_as_non_root
        run_as_non_root=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.securityContext.runAsNonRoot}' 2>/dev/null || echo "")
        
        if [[ "$run_as_non_root" == "true" ]]; then
            ((non_root_pods++))
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    local non_root_percentage=0
    if [[ $total_pods -gt 0 ]]; then
        non_root_percentage=$((non_root_pods * 100 / total_pods))
    fi

    if [[ $pods_with_latest_tag -eq 0 ]] && [[ $non_root_percentage -ge $COMPLIANCE_THRESHOLD ]]; then
        add_check_result "Image Security" "PASS" "No :latest tags found, $non_root_pods/$total_pods pods run as non-root, $pods_with_digest pods use digest pinning" "HIGH"
    else
        add_check_result "Image Security" "FAIL" "$pods_with_latest_tag pods use :latest tag, only $non_root_pods/$total_pods pods run as non-root" "HIGH" "Use specific image tags, enable runAsNonRoot, and implement image digest pinning"
    fi
}

# Check secrets management
check_secrets_management() {
    log_info "Checking secrets management..."

    local secrets_in_env=0
    local secrets_mounted=0
    local total_pods=0
    local csi_secrets=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        # Check for secrets in environment variables
        local env_secrets
        env_secrets=$(kubectl get pod "$pod_name" -n "$namespace" -o json 2>/dev/null | jq -r '.spec.containers[].env[]? | select(.valueFrom.secretKeyRef) | .name' | wc -l)
        
        if [[ $env_secrets -gt 0 ]]; then
            ((secrets_in_env++))
        fi

        # Check for mounted secrets
        local mounted_secrets
        mounted_secrets=$(kubectl get pod "$pod_name" -n "$namespace" -o json 2>/dev/null | jq -r '.spec.volumes[]? | select(.secret) | .name' | wc -l)
        
        if [[ $mounted_secrets -gt 0 ]]; then
            ((secrets_mounted++))
        fi

        # Check for CSI secrets
        local csi_volumes
        csi_volumes=$(kubectl get pod "$pod_name" -n "$namespace" -o json 2>/dev/null | jq -r '.spec.volumes[]? | select(.csi.driver == "secrets-store.csi.k8s.io") | .name' | wc -l)
        
        if [[ $csi_volumes -gt 0 ]]; then
            ((csi_secrets++))
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    if [[ $secrets_in_env -eq 0 ]] && [[ $csi_secrets -gt 0 ]]; then
        add_check_result "Secrets Management" "PASS" "No secrets in environment variables, $csi_secrets pods use CSI secrets, $secrets_mounted pods mount secrets" "MEDIUM"
    else
        add_check_result "Secrets Management" "FAIL" "$secrets_in_env pods have secrets in env vars, only $csi_secrets pods use CSI secrets" "MEDIUM" "Use Secrets Store CSI driver instead of environment variables for secrets"
    fi
}

# Calculate compliance summary
calculate_summary() {
    local total_checks passed_checks failed_checks compliance_percentage overall_status

    total_checks=$(jq '.checks | length' /tmp/compliance_results.json)
    passed_checks=$(jq '[.checks[] | select(.status == "PASS")] | length' /tmp/compliance_results.json)
    failed_checks=$(jq '[.checks[] | select(.status == "FAIL")] | length' /tmp/compliance_results.json)
    
    if [[ $total_checks -gt 0 ]]; then
        compliance_percentage=$((passed_checks * 100 / total_checks))
    else
        compliance_percentage=0
    fi

    if [[ $compliance_percentage -ge $COMPLIANCE_THRESHOLD ]]; then
        overall_status="COMPLIANT"
    else
        overall_status="NON_COMPLIANT"
    fi

    jq --argjson total "$total_checks" \
       --argjson passed "$passed_checks" \
       --argjson failed "$failed_checks" \
       --argjson percentage "$compliance_percentage" \
       --arg status "$overall_status" \
       '.summary.total_checks = $total | 
        .summary.passed_checks = $passed | 
        .summary.failed_checks = $failed | 
        .summary.compliance_percentage = $percentage | 
        .summary.overall_status = $status' \
       /tmp/compliance_results.json > /tmp/compliance_results_tmp.json
    
    mv /tmp/compliance_results_tmp.json /tmp/compliance_results.json
}

# Output results
output_results() {
    case $OUTPUT_FORMAT in
        json)
            cat /tmp/compliance_results.json
            ;;
        yaml)
            cat /tmp/compliance_results.json | yq eval -P
            ;;
        table)
            echo "Container Security Compliance Report"
            echo "===================================="
            echo "Cluster: $CLUSTER_NAME"
            echo "Namespace: $NAMESPACE"
            echo "Timestamp: $(jq -r '.timestamp' /tmp/compliance_results.json)"
            echo ""
            
            local overall_status compliance_percentage
            overall_status=$(jq -r '.summary.overall_status' /tmp/compliance_results.json)
            compliance_percentage=$(jq -r '.summary.compliance_percentage' /tmp/compliance_results.json)
            
            echo "Overall Status: $overall_status ($compliance_percentage%)"
            echo ""
            
            printf "%-30s %-10s %-50s\n" "Check Name" "Status" "Message"
            printf "%-30s %-10s %-50s\n" "----------" "------" "-------"
            
            jq -r '.checks[] | "\(.name)|\(.status)|\(.message)"' /tmp/compliance_results.json | \
            while IFS='|' read -r name status message; do
                printf "%-30s %-10s %-50s\n" "$name" "$status" "$message"
            done
            ;;
        *)
            log_error "Unknown output format: $OUTPUT_FORMAT"
            exit 1
            ;;
    esac
}

# Main execution
main() {
    parse_args "$@"
    check_prerequisites
    init_results

    log_info "Starting compliance validation for cluster: $CLUSTER_NAME"

    # Run all compliance checks
    check_pod_security_admission
    check_security_contexts
    check_network_policies
    check_rbac
    check_image_security
    check_secrets_management

    # Calculate summary and output results
    calculate_summary
    output_results

    # Exit with appropriate code
    local overall_status
    overall_status=$(jq -r '.summary.overall_status' /tmp/compliance_results.json)
    
    if [[ "$overall_status" == "COMPLIANT" ]]; then
        log_success "Compliance validation completed successfully"
        exit 0
    else
        log_error "Compliance validation failed"
        exit 1
    fi
}

# Cleanup on exit
cleanup() {
    rm -f /tmp/compliance_results.json /tmp/compliance_results_tmp.json
}

trap cleanup EXIT

# Run main function
main "$@"