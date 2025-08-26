#!/bin/bash

# CIS Kubernetes Benchmark Validation Script
# This script validates CIS Kubernetes Benchmark controls for container security
# Requirements: 4.2, 4.5

set -euo pipefail

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-}"
CIS_VERSION="${CIS_VERSION:-1.8}"
VERBOSE="${VERBOSE:-false}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-json}"
SKIP_MANUAL="${SKIP_MANUAL:-true}"

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

CIS Kubernetes Benchmark Validation

OPTIONS:
    -c, --cluster CLUSTER_NAME    EKS cluster name (required)
    -v, --version CIS_VERSION     CIS benchmark version (default: 1.8)
    --verbose                     Enable verbose output
    -f, --format FORMAT           Output format: json, yaml, table (default: json)
    --skip-manual                 Skip manual verification checks (default: true)
    -h, --help                    Show this help message

EXAMPLES:
    $0 --cluster production-eks
    $0 -c staging-eks --version 1.7 -f table
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
            -v|--version)
                CIS_VERSION="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --skip-manual)
                SKIP_MANUAL=true
                shift
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
    command -v aws >/dev/null 2>&1 || missing_tools+=("aws")

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    # Check kubectl context
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
}

# Initialize CIS results
init_cis_results() {
    cat > /tmp/cis_results.json << EOF
{
  "cluster_name": "$CLUSTER_NAME",
  "cis_version": "$CIS_VERSION",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "controls": [],
  "summary": {
    "total_controls": 0,
    "passed_controls": 0,
    "failed_controls": 0,
    "manual_controls": 0,
    "not_applicable": 0,
    "compliance_score": 0
  }
}
EOF
}

# Add CIS control result
add_cis_result() {
    local control_id="$1"
    local title="$2"
    local status="$3"
    local description="$4"
    local remediation="${5:-}"
    local level="${6:-1}"

    local result
    result=$(jq -n \
        --arg id "$control_id" \
        --arg title "$title" \
        --arg status "$status" \
        --arg description "$description" \
        --arg remediation "$remediation" \
        --argjson level "$level" \
        '{
            control_id: $id,
            title: $title,
            status: $status,
            description: $description,
            remediation: $remediation,
            level: $level,
            timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")
        }')

    jq --argjson result "$result" '.controls += [$result]' /tmp/cis_results.json > /tmp/cis_results_tmp.json
    mv /tmp/cis_results_tmp.json /tmp/cis_results.json
}

# CIS 5.1.1 - Minimize the admission of privileged containers
check_cis_5_1_1() {
    log_info "Checking CIS 5.1.1 - Minimize admission of privileged containers"

    local privileged_pods=0
    local total_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local privileged_containers
        privileged_containers=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null || echo "")
        
        if [[ "$privileged_containers" == *"true"* ]]; then
            ((privileged_pods++))
            [[ "$VERBOSE" == true ]] && log_warn "Privileged pod: $pod_name in $namespace"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    if [[ $privileged_pods -eq 0 ]]; then
        add_cis_result "5.1.1" "Minimize admission of privileged containers" "PASS" "No privileged containers found ($total_pods pods checked)" "" 1
    else
        add_cis_result "5.1.1" "Minimize admission of privileged containers" "FAIL" "$privileged_pods privileged containers found out of $total_pods pods" "Implement Pod Security Admission or admission controller to block privileged containers" 1
    fi
}

# CIS 5.1.2 - Minimize the admission of containers wishing to share the host process ID namespace
check_cis_5_1_2() {
    log_info "Checking CIS 5.1.2 - Minimize admission of containers sharing host PID namespace"

    local host_pid_pods=0
    local total_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local host_pid
        host_pid=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.hostPID}' 2>/dev/null || echo "")
        
        if [[ "$host_pid" == "true" ]]; then
            ((host_pid_pods++))
            [[ "$VERBOSE" == true ]] && log_warn "Host PID pod: $pod_name in $namespace"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    if [[ $host_pid_pods -eq 0 ]]; then
        add_cis_result "5.1.2" "Minimize admission of containers sharing host PID namespace" "PASS" "No containers sharing host PID namespace ($total_pods pods checked)" "" 1
    else
        add_cis_result "5.1.2" "Minimize admission of containers sharing host PID namespace" "FAIL" "$host_pid_pods containers sharing host PID namespace" "Remove hostPID: true from pod specifications" 1
    fi
}

# CIS 5.1.3 - Minimize the admission of containers wishing to share the host IPC namespace
check_cis_5_1_3() {
    log_info "Checking CIS 5.1.3 - Minimize admission of containers sharing host IPC namespace"

    local host_ipc_pods=0
    local total_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local host_ipc
        host_ipc=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.hostIPC}' 2>/dev/null || echo "")
        
        if [[ "$host_ipc" == "true" ]]; then
            ((host_ipc_pods++))
            [[ "$VERBOSE" == true ]] && log_warn "Host IPC pod: $pod_name in $namespace"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    if [[ $host_ipc_pods -eq 0 ]]; then
        add_cis_result "5.1.3" "Minimize admission of containers sharing host IPC namespace" "PASS" "No containers sharing host IPC namespace ($total_pods pods checked)" "" 1
    else
        add_cis_result "5.1.3" "Minimize admission of containers sharing host IPC namespace" "FAIL" "$host_ipc_pods containers sharing host IPC namespace" "Remove hostIPC: true from pod specifications" 1
    fi
}

# CIS 5.1.4 - Minimize the admission of containers wishing to share the host network namespace
check_cis_5_1_4() {
    log_info "Checking CIS 5.1.4 - Minimize admission of containers sharing host network namespace"

    local host_network_pods=0
    local total_pods=0
    local system_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local host_network
        host_network=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.hostNetwork}' 2>/dev/null || echo "")
        
        if [[ "$host_network" == "true" ]]; then
            ((host_network_pods++))
            
            # Allow system pods in kube-system namespace
            if [[ "$namespace" == "kube-system" ]]; then
                ((system_pods++))
            else
                [[ "$VERBOSE" == true ]] && log_warn "Host network pod: $pod_name in $namespace"
            fi
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    local non_system_host_network=$((host_network_pods - system_pods))

    if [[ $non_system_host_network -eq 0 ]]; then
        add_cis_result "5.1.4" "Minimize admission of containers sharing host network namespace" "PASS" "Only system pods use host network ($system_pods system pods, $total_pods total pods)" "" 1
    else
        add_cis_result "5.1.4" "Minimize admission of containers sharing host network namespace" "FAIL" "$non_system_host_network non-system containers sharing host network namespace" "Remove hostNetwork: true from non-system pod specifications" 1
    fi
}

# CIS 5.1.5 - Minimize the admission of containers with allowPrivilegeEscalation
check_cis_5_1_5() {
    log_info "Checking CIS 5.1.5 - Minimize admission of containers with allowPrivilegeEscalation"

    local privilege_escalation_pods=0
    local total_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local allow_privilege_escalation
        allow_privilege_escalation=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}' 2>/dev/null || echo "")
        
        if [[ "$allow_privilege_escalation" == *"true"* ]]; then
            ((privilege_escalation_pods++))
            [[ "$VERBOSE" == true ]] && log_warn "Privilege escalation pod: $pod_name in $namespace"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    if [[ $privilege_escalation_pods -eq 0 ]]; then
        add_cis_result "5.1.5" "Minimize admission of containers with allowPrivilegeEscalation" "PASS" "No containers with allowPrivilegeEscalation=true ($total_pods pods checked)" "" 1
    else
        add_cis_result "5.1.5" "Minimize admission of containers with allowPrivilegeEscalation" "FAIL" "$privilege_escalation_pods containers with allowPrivilegeEscalation=true" "Set allowPrivilegeEscalation: false in container securityContext" 1
    fi
}

# CIS 5.1.6 - Minimize the admission of root containers
check_cis_5_1_6() {
    log_info "Checking CIS 5.1.6 - Minimize admission of root containers"

    local root_containers=0
    local non_root_containers=0
    local total_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local run_as_non_root
        run_as_non_root=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.securityContext.runAsNonRoot}' 2>/dev/null || echo "")
        
        local run_as_user
        run_as_user=$(kubectl get pod "$pod_name" -n "$namespace" -o jsonpath='{.spec.securityContext.runAsUser}' 2>/dev/null || echo "")
        
        if [[ "$run_as_non_root" == "true" ]] || [[ -n "$run_as_user" && "$run_as_user" != "0" ]]; then
            ((non_root_containers++))
        else
            ((root_containers++))
            [[ "$VERBOSE" == true ]] && log_warn "Potential root container: $pod_name in $namespace"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    local non_root_percentage=0
    if [[ $total_pods -gt 0 ]]; then
        non_root_percentage=$((non_root_containers * 100 / total_pods))
    fi

    if [[ $non_root_percentage -ge 80 ]]; then
        add_cis_result "5.1.6" "Minimize admission of root containers" "PASS" "$non_root_containers/$total_pods containers run as non-root ($non_root_percentage%)" "" 1
    else
        add_cis_result "5.1.6" "Minimize admission of root containers" "FAIL" "Only $non_root_containers/$total_pods containers run as non-root ($non_root_percentage%)" "Set runAsNonRoot: true or runAsUser to non-zero value" 1
    fi
}

# CIS 5.2.1 - Minimize the admission of containers with capabilities
check_cis_5_2_1() {
    log_info "Checking CIS 5.2.1 - Minimize admission of containers with capabilities"

    local containers_with_caps=0
    local total_pods=0

    while IFS= read -r pod_info; do
        ((total_pods++))
        local pod_name namespace
        pod_name=$(echo "$pod_info" | cut -d' ' -f1)
        namespace=$(echo "$pod_info" | cut -d' ' -f2)

        local capabilities
        capabilities=$(kubectl get pod "$pod_name" -n "$namespace" -o json 2>/dev/null | jq -r '.spec.containers[].securityContext.capabilities.add[]?' 2>/dev/null || echo "")
        
        if [[ -n "$capabilities" ]]; then
            ((containers_with_caps++))
            [[ "$VERBOSE" == true ]] && log_warn "Container with capabilities: $pod_name in $namespace ($capabilities)"
        fi
    done < <(kubectl get pods --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace --no-headers)

    if [[ $containers_with_caps -eq 0 ]]; then
        add_cis_result "5.2.1" "Minimize admission of containers with capabilities" "PASS" "No containers with added capabilities ($total_pods pods checked)" "" 1
    else
        add_cis_result "5.2.1" "Minimize admission of containers with capabilities" "FAIL" "$containers_with_caps containers have added capabilities" "Remove unnecessary capabilities and use drop: [\"ALL\"] in securityContext" 1
    fi
}

# CIS 5.3.1 - Ensure that the CNI in use supports Network Policies
check_cis_5_3_1() {
    log_info "Checking CIS 5.3.1 - Ensure CNI supports Network Policies"

    # Check if network policies exist
    local network_policies
    network_policies=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)

    # Check for CNI that supports network policies (AWS VPC CNI with Calico, Cilium, etc.)
    local cni_info=""
    if kubectl get daemonset -n kube-system aws-node >/dev/null 2>&1; then
        cni_info="AWS VPC CNI detected"
        
        # Check for Calico
        if kubectl get daemonset -n kube-system calico-node >/dev/null 2>&1; then
            cni_info="$cni_info with Calico"
        fi
    fi

    if [[ $network_policies -gt 0 ]] && [[ -n "$cni_info" ]]; then
        add_cis_result "5.3.1" "Ensure CNI supports Network Policies" "PASS" "$network_policies network policies found, $cni_info" "" 1
    else
        add_cis_result "5.3.1" "Ensure CNI supports Network Policies" "FAIL" "Network policies not properly configured or CNI doesn't support them" "Install and configure a CNI that supports Network Policies (Calico, Cilium, etc.)" 1
    fi
}

# CIS 5.3.2 - Ensure that all Namespaces have Network Policies defined
check_cis_5_3_2() {
    log_info "Checking CIS 5.3.2 - Ensure all Namespaces have Network Policies"

    local namespaces_with_policies=0
    local total_namespaces=0
    local system_namespaces=("kube-system" "kube-public" "kube-node-lease")

    while IFS= read -r namespace; do
        ((total_namespaces++))
        
        # Skip system namespaces for this check
        local is_system=false
        for sys_ns in "${system_namespaces[@]}"; do
            if [[ "$namespace" == "$sys_ns" ]]; then
                is_system=true
                break
            fi
        done

        if [[ "$is_system" == false ]]; then
            local policy_count
            policy_count=$(kubectl get networkpolicies -n "$namespace" --no-headers 2>/dev/null | wc -l)
            
            if [[ $policy_count -gt 0 ]]; then
                ((namespaces_with_policies++))
            else
                [[ "$VERBOSE" == true ]] && log_warn "Namespace without network policies: $namespace"
            fi
        fi
    done < <(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')

    local user_namespaces=$((total_namespaces - ${#system_namespaces[@]}))
    local coverage_percentage=0
    if [[ $user_namespaces -gt 0 ]]; then
        coverage_percentage=$((namespaces_with_policies * 100 / user_namespaces))
    fi

    if [[ $coverage_percentage -ge 80 ]]; then
        add_cis_result "5.3.2" "Ensure all Namespaces have Network Policies" "PASS" "$namespaces_with_policies/$user_namespaces user namespaces have network policies ($coverage_percentage%)" "" 1
    else
        add_cis_result "5.3.2" "Ensure all Namespaces have Network Policies" "FAIL" "Only $namespaces_with_policies/$user_namespaces user namespaces have network policies ($coverage_percentage%)" "Create network policies for all application namespaces" 1
    fi
}

# CIS 5.7.1 - Create administrative boundaries between resources using namespaces
check_cis_5_7_1() {
    log_info "Checking CIS 5.7.1 - Administrative boundaries using namespaces"

    local total_namespaces
    total_namespaces=$(kubectl get namespaces --no-headers | wc -l)

    local pods_in_default
    pods_in_default=$(kubectl get pods -n default --no-headers 2>/dev/null | wc -l)

    local services_in_default
    services_in_default=$(kubectl get services -n default --no-headers 2>/dev/null | grep -v kubernetes | wc -l)

    if [[ $total_namespaces -ge 3 ]] && [[ $pods_in_default -eq 0 ]] && [[ $services_in_default -eq 0 ]]; then
        add_cis_result "5.7.1" "Administrative boundaries using namespaces" "PASS" "$total_namespaces namespaces exist, default namespace is empty" "" 1
    else
        add_cis_result "5.7.1" "Administrative boundaries using namespaces" "FAIL" "Insufficient namespace separation ($total_namespaces namespaces, $pods_in_default pods in default)" "Create separate namespaces for different applications and avoid using default namespace" 1
    fi
}

# Calculate CIS compliance summary
calculate_cis_summary() {
    local total_controls passed_controls failed_controls manual_controls not_applicable compliance_score

    total_controls=$(jq '.controls | length' /tmp/cis_results.json)
    passed_controls=$(jq '[.controls[] | select(.status == "PASS")] | length' /tmp/cis_results.json)
    failed_controls=$(jq '[.controls[] | select(.status == "FAIL")] | length' /tmp/cis_results.json)
    manual_controls=$(jq '[.controls[] | select(.status == "MANUAL")] | length' /tmp/cis_results.json)
    not_applicable=$(jq '[.controls[] | select(.status == "N/A")] | length' /tmp/cis_results.json)
    
    if [[ $total_controls -gt 0 ]]; then
        compliance_score=$((passed_controls * 100 / total_controls))
    else
        compliance_score=0
    fi

    jq --argjson total "$total_controls" \
       --argjson passed "$passed_controls" \
       --argjson failed "$failed_controls" \
       --argjson manual "$manual_controls" \
       --argjson na "$not_applicable" \
       --argjson score "$compliance_score" \
       '.summary.total_controls = $total | 
        .summary.passed_controls = $passed | 
        .summary.failed_controls = $failed | 
        .summary.manual_controls = $manual | 
        .summary.not_applicable = $na | 
        .summary.compliance_score = $score' \
       /tmp/cis_results.json > /tmp/cis_results_tmp.json
    
    mv /tmp/cis_results_tmp.json /tmp/cis_results.json
}

# Output CIS results
output_cis_results() {
    case $OUTPUT_FORMAT in
        json)
            cat /tmp/cis_results.json
            ;;
        yaml)
            cat /tmp/cis_results.json | yq eval -P
            ;;
        table)
            echo "CIS Kubernetes Benchmark v$CIS_VERSION Report"
            echo "============================================="
            echo "Cluster: $CLUSTER_NAME"
            echo "Timestamp: $(jq -r '.timestamp' /tmp/cis_results.json)"
            echo ""
            
            local compliance_score
            compliance_score=$(jq -r '.summary.compliance_score' /tmp/cis_results.json)
            
            echo "Compliance Score: $compliance_score%"
            echo ""
            
            printf "%-10s %-60s %-10s\n" "Control" "Title" "Status"
            printf "%-10s %-60s %-10s\n" "-------" "-----" "------"
            
            jq -r '.controls[] | "\(.control_id)|\(.title)|\(.status)"' /tmp/cis_results.json | \
            while IFS='|' read -r control title status; do
                printf "%-10s %-60s %-10s\n" "$control" "$title" "$status"
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
    init_cis_results

    log_info "Starting CIS Kubernetes Benchmark v$CIS_VERSION validation for cluster: $CLUSTER_NAME"

    # Run CIS checks
    check_cis_5_1_1
    check_cis_5_1_2
    check_cis_5_1_3
    check_cis_5_1_4
    check_cis_5_1_5
    check_cis_5_1_6
    check_cis_5_2_1
    check_cis_5_3_1
    check_cis_5_3_2
    check_cis_5_7_1

    # Calculate summary and output results
    calculate_cis_summary
    output_cis_results

    # Exit with appropriate code
    local compliance_score
    compliance_score=$(jq -r '.summary.compliance_score' /tmp/cis_results.json)
    
    if [[ $compliance_score -ge 80 ]]; then
        log_success "CIS benchmark validation completed with $compliance_score% compliance"
        exit 0
    else
        log_error "CIS benchmark validation failed with $compliance_score% compliance"
        exit 1
    fi
}

# Cleanup on exit
cleanup() {
    rm -f /tmp/cis_results.json /tmp/cis_results_tmp.json
}

trap cleanup EXIT

# Run main function
main "$@"