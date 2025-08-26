#!/bin/bash
# security-testing-framework.sh
# Comprehensive security validation and testing framework for AWS container security

set -e

# Configuration
CLUSTER_NAME=${1:-"secure-cluster"}
VALIDATION_NAMESPACE=${2:-"security-validation"}
CLEANUP=${3:-"true"}
REPORT_DIR="security-reports-$(date +%Y%m%d-%H%M%S)"
METRICS_FILE="$REPORT_DIR/security-metrics.json"
COMPLIANCE_REPORT="$REPORT_DIR/compliance-report.json"
VULNERABILITY_REPORT="$REPORT_DIR/vulnerability-report.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0

# Security metrics
CRITICAL_VULNERABILITIES=0
HIGH_VULNERABILITIES=0
MEDIUM_VULNERABILITIES=0
LOW_VULNERABILITIES=0
POLICY_VIOLATIONS=0
COMPLIANCE_SCORE=0

# Logging functions
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
    ((WARNING_TESTS++))
}

info() {
    echo -e "${PURPLE}ℹ️  $1${NC}"
}

# Initialize reporting structure
init_reports() {
    mkdir -p $REPORT_DIR
    
    # Initialize main metrics file
    cat > $METRICS_FILE << EOF
{
  "test_run": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cluster": "$CLUSTER_NAME",
    "namespace": "$VALIDATION_NAMESPACE",
    "framework_version": "1.0.0"
  },
  "security_metrics": {
    "vulnerabilities": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    },
    "policy_violations": 0,
    "compliance_score": 0,
    "mttr_hours": 0
  },
  "test_categories": {
    "admission_policies": {},
    "image_security": {},
    "network_security": {},
    "secrets_management": {},
    "infrastructure_security": {},
    "supply_chain": {},
    "monitoring_compliance": {}
  }
}
EOF

    # Initialize compliance report
    cat > $COMPLIANCE_REPORT << EOF
{
  "compliance_framework": "CIS Kubernetes Benchmark v1.7.0",
  "assessment_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cluster": "$CLUSTER_NAME",
  "controls": {},
  "summary": {
    "total_controls": 0,
    "passed": 0,
    "failed": 0,
    "not_applicable": 0,
    "overall_score": 0
  }
}
EOF

    # Initialize vulnerability report
    cat > $VULNERABILITY_REPORT << EOF
{
  "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cluster": "$CLUSTER_NAME",
  "images": {},
  "summary": {
    "total_images": 0,
    "vulnerable_images": 0,
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 0,
    "medium_vulnerabilities": 0,
    "low_vulnerabilities": 0
  }
}
EOF
}

# Update metrics
update_metrics() {
    local category=$1
    local test_name=$2
    local result=$3
    local details=$4
    local severity=${5:-"medium"}
    
    jq --arg cat "$category" --arg test "$test_name" --arg result "$result" --arg details "$details" --arg severity "$severity" \
       '.test_categories[$cat][$test] = {"result": $result, "details": $details, "severity": $severity, "timestamp": now | strftime("%Y-%m-%dT%H:%M:%SZ")}' \
       $METRICS_FILE > tmp.$.json && mv tmp.$.json $METRICS_FILE
}

# Run comprehensive admission policy tests
test_comprehensive_admission_policies() {
    log "Running comprehensive admission policy tests..."
    
    local test_cases=(
        "privileged-container:privileged=true:critical"
        "root-user:runAsUser=0:high"
        "privilege-escalation:allowPrivilegeEscalation=true:high"
        "writable-root:readOnlyRootFilesystem=false:medium"
        "host-network:hostNetwork=true:critical"
        "host-pid:hostPID=true:critical"
        "host-ipc:hostIPC=true:high"
        "unsafe-sysctls:sysctls=kernel.shm_rmid_forced=1:high"
        "capabilities-add:capabilities.add=SYS_ADMIN:high"
        "seccomp-unconfined:seccompProfile.type=Unconfined:medium"
    )
    
    for test_case in "${test_cases[@]}"; do
        local test_name=$(echo $test_case | cut -d: -f1)
        local test_config=$(echo $test_case | cut -d: -f2)
        local severity=$(echo $test_case | cut -d: -f3)
        
        ((TOTAL_TESTS++))
        
        log "Testing admission policy: $test_name (severity: $severity)"
        
        # Create test pod manifest
        local pod_manifest="/tmp/test-pod-$test_name.yaml"
        cat > $pod_manifest << EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-$test_name
  namespace: $VALIDATION_NAMESPACE
  labels:
    test-type: admission-policy
    severity: $severity
spec:
  containers:
  - name: test
    image: busybox:1.35
    command: ['sleep', '30']
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
EOF
        
        # Apply specific insecure configuration based on test
        case $test_name in
            "privileged-container")
                yq eval '.spec.containers[0].securityContext.privileged = true' -i $pod_manifest
                yq eval 'del(.spec.containers[0].securityContext.runAsNonRoot)' -i $pod_manifest
                ;;
            "root-user")
                yq eval '.spec.containers[0].securityContext.runAsUser = 0' -i $pod_manifest
                yq eval 'del(.spec.containers[0].securityContext.runAsNonRoot)' -i $pod_manifest
                ;;
            "privilege-escalation")
                yq eval '.spec.containers[0].securityContext.allowPrivilegeEscalation = true' -i $pod_manifest
                ;;
            "writable-root")
                yq eval 'del(.spec.containers[0].securityContext.readOnlyRootFilesystem)' -i $pod_manifest
                ;;
            "host-network")
                yq eval '.spec.hostNetwork = true' -i $pod_manifest
                ;;
            "host-pid")
                yq eval '.spec.hostPID = true' -i $pod_manifest
                ;;
            "host-ipc")
                yq eval '.spec.hostIPC = true' -i $pod_manifest
                ;;
            "unsafe-sysctls")
                yq eval '.spec.securityContext.sysctls = [{"name": "kernel.shm_rmid_forced", "value": "1"}]' -i $pod_manifest
                ;;
            "capabilities-add")
                yq eval '.spec.containers[0].securityContext.capabilities.add = ["SYS_ADMIN"]' -i $pod_manifest
                ;;
            "seccomp-unconfined")
                yq eval '.spec.securityContext.seccompProfile.type = "Unconfined"' -i $pod_manifest
                ;;
        esac
        
        # Try to create pod (should fail)
        if kubectl apply -f $pod_manifest &>/dev/null; then
            failure "Admission policy test failed: $test_name - Pod was allowed but should have been rejected"
            update_metrics "admission_policies" "$test_name" "FAIL" "Pod was allowed but should have been rejected" "$severity"
            ((POLICY_VIOLATIONS++))
        else
            success "Admission policy test passed: $test_name - Pod was correctly rejected"
            update_metrics "admission_policies" "$test_name" "PASS" "Pod was correctly rejected by admission policy" "$severity"
        fi
        
        # Cleanup
        kubectl delete -f $pod_manifest --ignore-not-found=true &>/dev/null
        rm -f $pod_manifest
    done
}

# Test image security and vulnerability scanning
test_image_security_comprehensive() {
    log "Running comprehensive image security tests..."
    
    ((TOTAL_TESTS++))
    
    # Test ECR repositories and scanning
    local ecr_repos=$(aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null || echo "")
    
    if [ -n "$ecr_repos" ]; then
        success "ECR repositories found: $(echo $ecr_repos | wc -w) repositories"
        update_metrics "image_security" "ecr_repositories" "PASS" "ECR repositories configured" "low"
        
        # Test image scanning for each repository
        for repo in $ecr_repos; do
            ((TOTAL_TESTS++))
            
            # Get latest image in repository
            local latest_image=$(aws ecr describe-images --repository-name $repo --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' --output text 2>/dev/null || echo "")
            
            if [ -n "$latest_image" ] && [ "$latest_image" != "None" ]; then
                # Check scan results
                local scan_results=$(aws ecr describe-image-scan-findings --repository-name $repo --image-id imageTag=$latest_image 2>/dev/null || echo "")
                
                if [ -n "$scan_results" ]; then
                    local critical=$(echo $scan_results | jq -r '.imageScanFindings.findingCounts.CRITICAL // 0')
                    local high=$(echo $scan_results | jq -r '.imageScanFindings.findingCounts.HIGH // 0')
                    local medium=$(echo $scan_results | jq -r '.imageScanFindings.findingCounts.MEDIUM // 0')
                    local low=$(echo $scan_results | jq -r '.imageScanFindings.findingCounts.LOW // 0')
                    
                    CRITICAL_VULNERABILITIES=$((CRITICAL_VULNERABILITIES + critical))
                    HIGH_VULNERABILITIES=$((HIGH_VULNERABILITIES + high))
                    MEDIUM_VULNERABILITIES=$((MEDIUM_VULNERABILITIES + medium))
                    LOW_VULNERABILITIES=$((LOW_VULNERABILITIES + low))
                    
                    # Update vulnerability report
                    jq --arg repo "$repo" --arg tag "$latest_image" --arg critical "$critical" --arg high "$high" --arg medium "$medium" --arg low "$low" \
                       '.images[$repo + ":" + $tag] = {"critical": ($critical | tonumber), "high": ($high | tonumber), "medium": ($medium | tonumber), "low": ($low | tonumber)}' \
                       $VULNERABILITY_REPORT > tmp.$.json && mv tmp.$.json $VULNERABILITY_REPORT
                    
                    if [ $critical -gt 0 ]; then
                        failure "Image $repo:$latest_image has $critical critical vulnerabilities"
                        update_metrics "image_security" "$repo-vulnerabilities" "FAIL" "$critical critical, $high high vulnerabilities" "critical"
                    elif [ $high -gt 5 ]; then
                        warning "Image $repo:$latest_image has $high high vulnerabilities (threshold: 5)"
                        update_metrics "image_security" "$repo-vulnerabilities" "WARN" "$high high vulnerabilities exceed threshold" "high"
                    else
                        success "Image $repo:$latest_image vulnerability scan passed"
                        update_metrics "image_security" "$repo-vulnerabilities" "PASS" "Vulnerabilities within acceptable limits" "low"
                    fi
                else
                    warning "No scan results found for $repo:$latest_image"
                    update_metrics "image_security" "$repo-scan-status" "WARN" "No scan results available" "medium"
                fi
            else
                warning "No images found in repository $repo"
                update_metrics "image_security" "$repo-images" "WARN" "No images found in repository" "low"
            fi
        done
    else
        failure "No ECR repositories found"
        update_metrics "image_security" "ecr_repositories" "FAIL" "No ECR repositories configured" "high"
    fi
}

# Test network security policies
test_network_security_comprehensive() {
    log "Running comprehensive network security tests..."
    
    # Test default deny policies
    ((TOTAL_TESTS++))
    
    # Check for default deny network policies
    local default_deny_policies=$(kubectl get networkpolicy --all-namespaces -o json | jq -r '.items[] | select(.spec.podSelector == {} and (.spec.policyTypes | contains(["Ingress", "Egress"]))) | .metadata.name' 2>/dev/null || echo "")
    
    if [ -n "$default_deny_policies" ]; then
        success "Default deny network policies found: $(echo $default_deny_policies | wc -w) policies"
        update_metrics "network_security" "default_deny_policies" "PASS" "Default deny policies configured" "medium"
    else
        failure "No default deny network policies found"
        update_metrics "network_security" "default_deny_policies" "FAIL" "Default deny policies not configured" "high"
    fi
    
    # Test Security Groups for Pods (if available)
    ((TOTAL_TESTS++))
    
    if kubectl get crd securitygrouppolicies.vpcresources.k8s.aws &>/dev/null; then
        local sgp_policies=$(kubectl get securitygrouppolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
        if [ $sgp_policies -gt 0 ]; then
            success "Security Groups for Pods configured: $sgp_policies policies"
            update_metrics "network_security" "security_groups_for_pods" "PASS" "$sgp_policies SGP policies configured" "medium"
        else
            warning "Security Groups for Pods CRD found but no policies configured"
            update_metrics "network_security" "security_groups_for_pods" "WARN" "SGP available but not configured" "medium"
        fi
    else
        info "Security Groups for Pods not available (requires VPC CNI)"
        update_metrics "network_security" "security_groups_for_pods" "INFO" "SGP not available" "low"
    fi
    
    # Test network connectivity isolation
    test_network_isolation
}

# Test network isolation with actual connectivity tests
test_network_isolation() {
    log "Testing network isolation with connectivity tests..."
    
    ((TOTAL_TESTS++))
    
    # Create test pods in different namespaces
    kubectl create namespace network-test-source --dry-run=client -o yaml | kubectl apply -f - &>/dev/null
    kubectl create namespace network-test-target --dry-run=client -o yaml | kubectl apply -f - &>/dev/null
    
    # Apply default deny to target namespace
    kubectl apply -f - << EOF &>/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: network-test-target
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
    
    # Create source pod
    kubectl apply -f - << EOF &>/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: network-source
  namespace: network-test-source
spec:
  containers:
  - name: source
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
    
    # Create target pod
    kubectl apply -f - << EOF &>/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: network-target
  namespace: network-test-target
spec:
  containers:
  - name: target
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
    kubectl wait --for=condition=Ready pod/network-source -n network-test-source --timeout=60s &>/dev/null
    kubectl wait --for=condition=Ready pod/network-target -n network-test-target --timeout=60s &>/dev/null
    
    # Get target pod IP
    local target_ip=$(kubectl get pod network-target -n network-test-target -o jsonpath='{.status.podIP}')
    
    # Test connectivity (should fail due to network policy)
    sleep 10  # Allow policy to take effect
    
    if kubectl exec network-source -n network-test-source -- timeout 5 nc -z $target_ip 80 &>/dev/null; then
        failure "Network isolation test failed - Connection allowed when should be blocked"
        update_metrics "network_security" "network_isolation" "FAIL" "Cross-namespace connection allowed despite deny policy" "high"
    else
        success "Network isolation test passed - Connection correctly blocked"
        update_metrics "network_security" "network_isolation" "PASS" "Cross-namespace connection correctly blocked" "medium"
    fi
    
    # Cleanup network test resources
    kubectl delete namespace network-test-source network-test-target --ignore-not-found=true &>/dev/null
}

# Test secrets management security
test_secrets_management_comprehensive() {
    log "Running comprehensive secrets management tests..."
    
    # Test Secrets Store CSI Driver
    ((TOTAL_TESTS++))
    
    if kubectl get csidriver secrets-store.csi.k8s.io &>/dev/null; then
        success "Secrets Store CSI Driver installed"
        update_metrics "secrets_management" "csi_driver" "PASS" "Secrets Store CSI Driver installed" "medium"
        
        # Test AWS provider
        if kubectl get daemonset csi-secrets-store-provider-aws -n kube-system &>/dev/null; then
            success "AWS Secrets Store provider installed"
            update_metrics "secrets_management" "aws_provider" "PASS" "AWS provider installed" "medium"
        else
            warning "AWS Secrets Store provider not found"
            update_metrics "secrets_management" "aws_provider" "WARN" "AWS provider not installed" "medium"
        fi
    else
        failure "Secrets Store CSI Driver not installed"
        update_metrics "secrets_management" "csi_driver" "FAIL" "CSI driver not installed" "high"
    fi
    
    # Test for secrets in container images
    test_secrets_in_images
    
    # Test KMS encryption
    test_kms_encryption
}

# Test for secrets embedded in container images
test_secrets_in_images() {
    log "Scanning for secrets in container images..."
    
    ((TOTAL_TESTS++))
    
    # Get all pods and scan their images for potential secrets
    local pods=$(kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.status.phase == "Running") | "\(.metadata.namespace)/\(.metadata.name)"')
    local secrets_found=0
    
    for pod in $pods; do
        local namespace=$(echo $pod | cut -d/ -f1)
        local pod_name=$(echo $pod | cut -d/ -f2)
        
        # Skip system pods
        if [[ $namespace =~ ^(kube-system|kube-public|amazon-cloudwatch)$ ]]; then
            continue
        fi
        
        # Get pod images
        local images=$(kubectl get pod $pod_name -n $namespace -o json | jq -r '.spec.containers[].image')
        
        for image in $images; do
            # Simple check for common secret patterns in environment variables
            local env_vars=$(kubectl get pod $pod_name -n $namespace -o json | jq -r '.spec.containers[].env[]? | select(.value) | .value' 2>/dev/null || echo "")
            
            if echo "$env_vars" | grep -qiE "(password|secret|key|token)" 2>/dev/null; then
                warning "Potential secrets found in environment variables for pod $pod_name in namespace $namespace"
                ((secrets_found++))
            fi
        done
    done
    
    if [ $secrets_found -eq 0 ]; then
        success "No obvious secrets found in pod environment variables"
        update_metrics "secrets_management" "secrets_in_env" "PASS" "No secrets detected in environment variables" "medium"
    else
        failure "Found $secrets_found potential secrets in pod environment variables"
        update_metrics "secrets_management" "secrets_in_env" "FAIL" "$secrets_found potential secrets found" "high"
    fi
}

# Test KMS encryption configuration
test_kms_encryption() {
    log "Testing KMS encryption configuration..."
    
    ((TOTAL_TESTS++))
    
    # Check EKS cluster encryption configuration
    local cluster_encryption=$(aws eks describe-cluster --name $CLUSTER_NAME --query 'cluster.encryptionConfig' --output json 2>/dev/null || echo "[]")
    
    if [ "$cluster_encryption" != "[]" ] && [ "$cluster_encryption" != "null" ]; then
        success "EKS cluster encryption configured"
        update_metrics "secrets_management" "cluster_encryption" "PASS" "EKS cluster encryption enabled" "medium"
    else
        failure "EKS cluster encryption not configured"
        update_metrics "secrets_management" "cluster_encryption" "FAIL" "EKS cluster encryption not enabled" "high"
    fi
}

# Test infrastructure security
test_infrastructure_security() {
    log "Running infrastructure security tests..."
    
    # Test node security groups
    ((TOTAL_TESTS++))
    
    local node_groups=$(aws eks describe-nodegroup --cluster-name $CLUSTER_NAME --nodegroup-name $(aws eks list-nodegroups --cluster-name $CLUSTER_NAME --query 'nodegroups[0]' --output text) --query 'nodegroup.remoteAccess' --output json 2>/dev/null || echo "{}")
    
    if echo "$node_groups" | jq -e '.ec2SshKey' &>/dev/null; then
        warning "SSH access configured for node groups - consider disabling for production"
        update_metrics "infrastructure_security" "ssh_access" "WARN" "SSH access enabled on node groups" "medium"
    else
        success "SSH access not configured for node groups"
        update_metrics "infrastructure_security" "ssh_access" "PASS" "SSH access disabled" "low"
    fi
    
    # Test private cluster configuration
    ((TOTAL_TESTS++))
    
    local endpoint_config=$(aws eks describe-cluster --name $CLUSTER_NAME --query 'cluster.resourcesVpcConfig' --output json 2>/dev/null || echo "{}")
    local private_access=$(echo "$endpoint_config" | jq -r '.endpointPrivateAccess')
    local public_access=$(echo "$endpoint_config" | jq -r '.endpointPublicAccess')
    
    if [ "$private_access" = "true" ] && [ "$public_access" = "false" ]; then
        success "Cluster configured with private endpoint only"
        update_metrics "infrastructure_security" "private_endpoint" "PASS" "Private endpoint configuration" "medium"
    elif [ "$private_access" = "true" ] && [ "$public_access" = "true" ]; then
        warning "Cluster has both private and public endpoints enabled"
        update_metrics "infrastructure_security" "private_endpoint" "WARN" "Mixed endpoint configuration" "medium"
    else
        failure "Cluster not configured with private endpoint"
        update_metrics "infrastructure_security" "private_endpoint" "FAIL" "Public endpoint only" "high"
    fi
}

# Test supply chain security
test_supply_chain_security() {
    log "Running supply chain security tests..."
    
    # Test for image signing verification
    ((TOTAL_TESTS++))
    
    if command -v cosign &>/dev/null; then
        success "Cosign available for image signature verification"
        update_metrics "supply_chain" "cosign_available" "PASS" "Cosign tool available" "medium"
        
        # Test admission controller policies for image verification
        local admission_policies=$(kubectl get validatingadmissionpolicies -o json 2>/dev/null | jq -r '.items[] | select(.spec.matchConstraints.resourceRules[]?.resources[]? == "pods") | .metadata.name' || echo "")
        
        if [ -n "$admission_policies" ]; then
            success "Admission policies found for pod validation"
            update_metrics "supply_chain" "admission_policies" "PASS" "Admission policies configured" "medium"
        else
            warning "No admission policies found for pod validation"
            update_metrics "supply_chain" "admission_policies" "WARN" "No admission policies configured" "medium"
        fi
    else
        warning "Cosign not available - image signing verification not possible"
        update_metrics "supply_chain" "cosign_available" "WARN" "Cosign not installed" "medium"
    fi
    
    # Test SBOM generation capability
    ((TOTAL_TESTS++))
    
    if command -v syft &>/dev/null; then
        success "Syft available for SBOM generation"
        update_metrics "supply_chain" "sbom_generation" "PASS" "SBOM generation capability available" "low"
    else
        warning "Syft not available - SBOM generation not possible"
        update_metrics "supply_chain" "sbom_generation" "WARN" "SBOM generation not available" "medium"
    fi
}

# Test monitoring and compliance
test_monitoring_compliance() {
    log "Running monitoring and compliance tests..."
    
    # Test GuardDuty EKS protection
    ((TOTAL_TESTS++))
    
    local guardduty_detectors=$(aws guardduty list-detectors --query 'DetectorIds' --output text 2>/dev/null || echo "")
    
    if [ -n "$guardduty_detectors" ]; then
        local detector_id=$(echo $guardduty_detectors | awk '{print $1}')
        local eks_protection=$(aws guardduty get-detector --detector-id $detector_id --query 'Features[?Name==`EKS_AUDIT_LOGS`].Status' --output text 2>/dev/null || echo "")
        
        if [ "$eks_protection" = "ENABLED" ]; then
            success "GuardDuty EKS protection enabled"
            update_metrics "monitoring_compliance" "guardduty_eks" "PASS" "GuardDuty EKS protection enabled" "medium"
        else
            warning "GuardDuty found but EKS protection not enabled"
            update_metrics "monitoring_compliance" "guardduty_eks" "WARN" "EKS protection not enabled" "medium"
        fi
    else
        failure "GuardDuty not configured"
        update_metrics "monitoring_compliance" "guardduty_eks" "FAIL" "GuardDuty not configured" "high"
    fi
    
    # Test CloudTrail logging
    ((TOTAL_TESTS++))
    
    local cloudtrail_trails=$(aws cloudtrail describe-trails --query 'trailList[?IsLogging==`true`].Name' --output text 2>/dev/null || echo "")
    
    if [ -n "$cloudtrail_trails" ]; then
        success "CloudTrail logging enabled: $(echo $cloudtrail_trails | wc -w) active trails"
        update_metrics "monitoring_compliance" "cloudtrail" "PASS" "CloudTrail logging active" "medium"
    else
        failure "No active CloudTrail logging found"
        update_metrics "monitoring_compliance" "cloudtrail" "FAIL" "CloudTrail not configured" "high"
    fi
    
    # Run CIS Kubernetes benchmark if available
    run_cis_benchmark
}

# Run CIS Kubernetes benchmark
run_cis_benchmark() {
    log "Running CIS Kubernetes benchmark..."
    
    if [ -f "./monitoring-compliance/validation/cis-kubernetes-benchmark.sh" ]; then
        local cis_results=$(./monitoring-compliance/validation/cis-kubernetes-benchmark.sh 2>/dev/null || echo "")
        
        if [ -n "$cis_results" ]; then
            # Parse CIS results and update compliance report
            local passed_controls=$(echo "$cis_results" | grep -c "PASS" || echo "0")
            local failed_controls=$(echo "$cis_results" | grep -c "FAIL" || echo "0")
            local total_controls=$((passed_controls + failed_controls))
            
            if [ $total_controls -gt 0 ]; then
                local compliance_score=$(( (passed_controls * 100) / total_controls ))
                COMPLIANCE_SCORE=$compliance_score
                
                jq --arg passed "$passed_controls" --arg failed "$failed_controls" --arg total "$total_controls" --arg score "$compliance_score" \
                   '.summary = {"total_controls": ($total | tonumber), "passed": ($passed | tonumber), "failed": ($failed | tonumber), "not_applicable": 0, "overall_score": ($score | tonumber)}' \
                   $COMPLIANCE_REPORT > tmp.$.json && mv tmp.$.json $COMPLIANCE_REPORT
                
                if [ $compliance_score -ge 80 ]; then
                    success "CIS benchmark compliance: $compliance_score% ($passed_controls/$total_controls)"
                    update_metrics "monitoring_compliance" "cis_benchmark" "PASS" "CIS compliance score: $compliance_score%" "medium"
                else
                    failure "CIS benchmark compliance below threshold: $compliance_score% ($passed_controls/$total_controls)"
                    update_metrics "monitoring_compliance" "cis_benchmark" "FAIL" "CIS compliance score: $compliance_score%" "high"
                fi
            else
                warning "CIS benchmark completed but no results parsed"
                update_metrics "monitoring_compliance" "cis_benchmark" "WARN" "CIS benchmark results unclear" "medium"
            fi
        else
            warning "CIS benchmark script executed but no output received"
            update_metrics "monitoring_compliance" "cis_benchmark" "WARN" "CIS benchmark execution unclear" "medium"
        fi
    else
        info "CIS benchmark script not found, skipping detailed compliance check"
        update_metrics "monitoring_compliance" "cis_benchmark" "INFO" "CIS benchmark script not available" "low"
    fi
}

# Generate comprehensive security metrics
generate_security_metrics() {
    log "Generating comprehensive security metrics..."
    
    # Update final metrics
    jq --arg critical "$CRITICAL_VULNERABILITIES" --arg high "$HIGH_VULNERABILITIES" --arg medium "$MEDIUM_VULNERABILITIES" --arg low "$LOW_VULNERABILITIES" --arg violations "$POLICY_VIOLATIONS" --arg compliance "$COMPLIANCE_SCORE" \
       '.security_metrics = {"vulnerabilities": {"critical": ($critical | tonumber), "high": ($high | tonumber), "medium": ($medium | tonumber), "low": ($low | tonumber)}, "policy_violations": ($violations | tonumber), "compliance_score": ($compliance | tonumber), "mttr_hours": 0}' \
       $METRICS_FILE > tmp.$.json && mv tmp.$.json $METRICS_FILE
    
    # Update vulnerability report summary
    local total_images=$(jq '.images | length' $VULNERABILITY_REPORT)
    local vulnerable_images=$(jq '[.images[] | select(.critical > 0 or .high > 0 or .medium > 0 or .low > 0)] | length' $VULNERABILITY_REPORT)
    
    jq --arg total "$total_images" --arg vulnerable "$vulnerable_images" --arg critical "$CRITICAL_VULNERABILITIES" --arg high "$HIGH_VULNERABILITIES" --arg medium "$MEDIUM_VULNERABILITIES" --arg low "$LOW_VULNERABILITIES" \
       '.summary = {"total_images": ($total | tonumber), "vulnerable_images": ($vulnerable | tonumber), "critical_vulnerabilities": ($critical | tonumber), "high_vulnerabilities": ($high | tonumber), "medium_vulnerabilities": ($medium | tonumber), "low_vulnerabilities": ($low | tonumber)}' \
       $VULNERABILITY_REPORT > tmp.$.json && mv tmp.$.json $VULNERABILITY_REPORT
}

# Generate final comprehensive report
generate_final_report() {
    log "Generating final comprehensive security report..."
    
    generate_security_metrics
    
    # Create summary report
    local summary_report="$REPORT_DIR/executive-summary.json"
    cat > $summary_report << EOF
{
  "executive_summary": {
    "assessment_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cluster": "$CLUSTER_NAME",
    "overall_security_posture": "$([ $FAILED_TESTS -eq 0 ] && echo "SECURE" || echo "NEEDS_ATTENTION")",
    "risk_level": "$([ $CRITICAL_VULNERABILITIES -gt 0 ] && echo "HIGH" || [ $HIGH_VULNERABILITIES -gt 10 ] && echo "MEDIUM" || echo "LOW")",
    "test_results": {
      "total_tests": $TOTAL_TESTS,
      "passed": $PASSED_TESTS,
      "failed": $FAILED_TESTS,
      "warnings": $WARNING_TESTS,
      "success_rate": $([ $TOTAL_TESTS -gt 0 ] && echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc || echo "0")
    },
    "security_metrics": {
      "critical_vulnerabilities": $CRITICAL_VULNERABILITIES,
      "high_vulnerabilities": $HIGH_VULNERABILITIES,
      "policy_violations": $POLICY_VIOLATIONS,
      "compliance_score": $COMPLIANCE_SCORE
    },
    "recommendations": []
  }
}
EOF
    
    # Add recommendations based on findings
    if [ $CRITICAL_VULNERABILITIES -gt 0 ]; then
        jq '.executive_summary.recommendations += ["Immediately address critical vulnerabilities in container images"]' $summary_report > tmp.$.json && mv tmp.$.json $summary_report
    fi
    
    if [ $POLICY_VIOLATIONS -gt 0 ]; then
        jq '.executive_summary.recommendations += ["Review and strengthen admission control policies"]' $summary_report > tmp.$.json && mv tmp.$.json $summary_report
    fi
    
    if [ $COMPLIANCE_SCORE -lt 80 ]; then
        jq '.executive_summary.recommendations += ["Improve CIS Kubernetes benchmark compliance"]' $summary_report > tmp.$.json && mv tmp.$.json $summary_report
    fi
    
    # Display summary
    echo
    echo "========================================="
    echo "COMPREHENSIVE SECURITY ASSESSMENT SUMMARY"
    echo "========================================="
    echo "Cluster: $CLUSTER_NAME"
    echo "Assessment Date: $(date)"
    echo
    echo "Test Results:"
    echo "  Total Tests: $TOTAL_TESTS"
    echo "  Passed: $PASSED_TESTS"
    echo "  Failed: $FAILED_TESTS"
    echo "  Warnings: $WARNING_TESTS"
    echo "  Success Rate: $([ $TOTAL_TESTS -gt 0 ] && echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc || echo "0")%"
    echo
    echo "Security Metrics:"
    echo "  Critical Vulnerabilities: $CRITICAL_VULNERABILITIES"
    echo "  High Vulnerabilities: $HIGH_VULNERABILITIES"
    echo "  Policy Violations: $POLICY_VIOLATIONS"
    echo "  Compliance Score: $COMPLIANCE_SCORE%"
    echo
    echo "Reports Generated:"
    echo "  📊 Executive Summary: $summary_report"
    echo "  📈 Security Metrics: $METRICS_FILE"
    echo "  🛡️  Compliance Report: $COMPLIANCE_REPORT"
    echo "  🔍 Vulnerability Report: $VULNERABILITY_REPORT"
    echo
    
    if [ $FAILED_TESTS -gt 0 ] || [ $CRITICAL_VULNERABILITIES -gt 0 ]; then
        echo -e "${RED}❌ SECURITY ASSESSMENT FAILED${NC}"
        echo "Critical issues found that require immediate attention."
        return 1
    elif [ $WARNING_TESTS -gt 0 ] || [ $HIGH_VULNERABILITIES -gt 5 ]; then
        echo -e "${YELLOW}⚠️  SECURITY ASSESSMENT COMPLETED WITH WARNINGS${NC}"
        echo "Some issues found that should be addressed."
        return 0
    else
        echo -e "${GREEN}✅ SECURITY ASSESSMENT PASSED${NC}"
        echo "Container security implementation meets security standards."
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

# Prerequisites check
check_prerequisites() {
    log "Checking prerequisites for comprehensive security testing..."
    
    # Check required tools
    local required_tools=("kubectl" "aws" "jq" "yq" "bc")
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            failure "Required tool not found: $tool"
            exit 1
        fi
    done
    
    success "All required tools available"
    
    # Check cluster connectivity
    if ! kubectl cluster-info &>/dev/null; then
        failure "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    success "Kubernetes cluster connectivity verified"
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        failure "AWS credentials not configured or invalid"
        exit 1
    fi
    
    success "AWS credentials verified"
    
    # Create validation namespace
    kubectl create namespace $VALIDATION_NAMESPACE --dry-run=client -o yaml | \
    kubectl label --local -f - \
      pod-security.kubernetes.io/enforce=restricted \
      pod-security.kubernetes.io/audit=restricted \
      pod-security.kubernetes.io/warn=restricted \
      -o yaml | kubectl apply -f - &>/dev/null
    
    success "Validation namespace prepared"
}

# Main execution function
main() {
    echo "========================================="
    echo "AWS Container Security Testing Framework"
    echo "========================================="
    echo "Version: 1.0.0"
    echo "Cluster: $CLUSTER_NAME"
    echo "Validation Namespace: $VALIDATION_NAMESPACE"
    echo "Report Directory: $REPORT_DIR"
    echo "Cleanup: $CLEANUP"
    echo
    
    init_reports
    check_prerequisites
    
    log "Starting comprehensive security testing..."
    
    test_comprehensive_admission_policies
    test_image_security_comprehensive
    test_network_security_comprehensive
    test_secrets_management_comprehensive
    test_infrastructure_security
    test_supply_chain_security
    test_monitoring_compliance
    
    generate_final_report
    local exit_code=$?
    
    cleanup
    
    exit $exit_code
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"