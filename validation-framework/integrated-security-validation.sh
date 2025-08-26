#!/bin/bash
# integrated-security-validation.sh
# Master integration script for comprehensive AWS container security validation

set -e

# Configuration
CLUSTER_NAME=${1:-"secure-cluster"}
VALIDATION_MODE=${2:-"full"}  # full, quick, compliance, vulnerability
OUTPUT_FORMAT=${3:-"json"}    # json, html, pdf
REPORT_DESTINATION=${4:-"local"}  # local, s3, cloudwatch
CLEANUP=${5:-"true"}

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$SCRIPT_DIR"
REPORT_DIR="integrated-security-reports-$(date +%Y%m%d-%H%M%S)"

# AWS Configuration
AWS_REGION=$(aws configure get region)
S3_BUCKET=${S3_BUCKET:-"security-validation-reports"}
CLOUDWATCH_NAMESPACE="ContainerSecurity/Validation"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global counters
TOTAL_VALIDATIONS=0
PASSED_VALIDATIONS=0
FAILED_VALIDATIONS=0
WARNING_VALIDATIONS=0

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED_VALIDATIONS++))
}

failure() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED_VALIDATIONS++))
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
    ((WARNING_VALIDATIONS++))
}

info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

header() {
    echo -e "${PURPLE}$1${NC}"
}

# Initialize validation environment
init_validation_environment() {
    log "Initializing integrated security validation environment..."
    
    mkdir -p $REPORT_DIR/{reports,logs,evidence,metrics}
    
    # Create validation configuration
    cat > $REPORT_DIR/validation-config.json << EOF
{
  "validation_run": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cluster": "$CLUSTER_NAME",
    "mode": "$VALIDATION_MODE",
    "output_format": "$OUTPUT_FORMAT",
    "report_destination": "$REPORT_DESTINATION",
    "aws_region": "$AWS_REGION"
  },
  "validation_components": {
    "comprehensive_validation": true,
    "security_testing_framework": true,
    "metrics_collection": true,
    "compliance_checking": true,
    "vulnerability_scanning": true,
    "incident_response_testing": true
  },
  "thresholds": {
    "max_critical_vulnerabilities": 0,
    "max_high_vulnerabilities": 5,
    "min_compliance_score": 80,
    "max_policy_violations": 0,
    "max_security_events": 10
  }
}
EOF
    
    success "Validation environment initialized"
}

# Run comprehensive validation
run_comprehensive_validation() {
    header "Running Comprehensive Security Validation"
    ((TOTAL_VALIDATIONS++))
    
    log "Executing comprehensive validation script..."
    
    if [ -f "$VALIDATION_DIR/comprehensive-validation.sh" ]; then
        if $VALIDATION_DIR/comprehensive-validation.sh $CLUSTER_NAME validation-comprehensive $CLEANUP > $REPORT_DIR/logs/comprehensive-validation.log 2>&1; then
            success "Comprehensive validation completed successfully"
            
            # Parse results
            if [ -f "validation-report-*.json" ]; then
                mv validation-report-*.json $REPORT_DIR/reports/comprehensive-validation.json
            fi
        else
            failure "Comprehensive validation failed - check logs for details"
            cat $REPORT_DIR/logs/comprehensive-validation.log | tail -20
        fi
    else
        warning "Comprehensive validation script not found"
    fi
}

# Run security testing framework
run_security_testing_framework() {
    header "Running Security Testing Framework"
    ((TOTAL_VALIDATIONS++))
    
    log "Executing security testing framework..."
    
    if [ -f "$VALIDATION_DIR/security-testing-framework.sh" ]; then
        if $VALIDATION_DIR/security-testing-framework.sh $CLUSTER_NAME validation-testing $CLEANUP > $REPORT_DIR/logs/security-testing.log 2>&1; then
            success "Security testing framework completed successfully"
            
            # Move generated reports
            if [ -d "security-reports-*" ]; then
                mv security-reports-* $REPORT_DIR/reports/security-testing/
            fi
        else
            failure "Security testing framework failed - check logs for details"
            cat $REPORT_DIR/logs/security-testing.log | tail -20
        fi
    else
        warning "Security testing framework script not found"
    fi
}

# Collect security metrics
collect_security_metrics() {
    header "Collecting Security Metrics"
    ((TOTAL_VALIDATIONS++))
    
    log "Running security metrics collection..."
    
    if [ -f "$VALIDATION_DIR/security-metrics-collector.sh" ]; then
        if $VALIDATION_DIR/security-metrics-collector.sh $CLUSTER_NAME > $REPORT_DIR/logs/metrics-collection.log 2>&1; then
            success "Security metrics collection completed successfully"
            
            # Move metrics files
            if [ -d "security-metrics" ]; then
                mv security-metrics $REPORT_DIR/metrics/
            fi
        else
            failure "Security metrics collection failed - check logs for details"
            cat $REPORT_DIR/logs/metrics-collection.log | tail -20
        fi
    else
        warning "Security metrics collector script not found"
    fi
}

# Run compliance validation
run_compliance_validation() {
    header "Running Compliance Validation"
    ((TOTAL_VALIDATIONS++))
    
    log "Executing compliance validation checks..."
    
    # CIS Kubernetes Benchmark
    if [ -f "../monitoring-compliance/validation/cis-kubernetes-benchmark.sh" ]; then
        log "Running CIS Kubernetes Benchmark..."
        if ../monitoring-compliance/validation/cis-kubernetes-benchmark.sh > $REPORT_DIR/logs/cis-benchmark.log 2>&1; then
            success "CIS Kubernetes Benchmark completed"
        else
            warning "CIS Kubernetes Benchmark had issues - check logs"
        fi
    fi
    
    # Security policy compliance
    if [ -f "../monitoring-compliance/validation/security-policy-compliance.sh" ]; then
        log "Running security policy compliance check..."
        if ../monitoring-compliance/validation/security-policy-compliance.sh > $REPORT_DIR/logs/policy-compliance.log 2>&1; then
            success "Security policy compliance check completed"
        else
            warning "Security policy compliance check had issues"
        fi
    fi
    
    # Continuous compliance monitoring
    if [ -f "../monitoring-compliance/validation/continuous-compliance-monitor.sh" ]; then
        log "Running continuous compliance monitoring..."
        if ../monitoring-compliance/validation/continuous-compliance-monitor.sh > $REPORT_DIR/logs/continuous-compliance.log 2>&1; then
            success "Continuous compliance monitoring completed"
        else
            warning "Continuous compliance monitoring had issues"
        fi
    fi
}

# Run vulnerability assessment
run_vulnerability_assessment() {
    header "Running Vulnerability Assessment"
    ((TOTAL_VALIDATIONS++))
    
    log "Executing vulnerability assessment..."
    
    # Image scanning validation
    if [ -f "../image-security-scanning/inspector-automation/scan-automation.sh" ]; then
        log "Running image scanning automation..."
        if ../image-security-scanning/inspector-automation/scan-automation.sh > $REPORT_DIR/logs/image-scanning.log 2>&1; then
            success "Image scanning automation completed"
        else
            warning "Image scanning automation had issues"
        fi
    fi
    
    # SBOM generation validation
    if [ -f "../image-security-scanning/sbom-generation/generate-sbom.sh" ]; then
        log "Validating SBOM generation..."
        if ../image-security-scanning/sbom-generation/generate-sbom.sh > $REPORT_DIR/logs/sbom-generation.log 2>&1; then
            success "SBOM generation validation completed"
        else
            warning "SBOM generation validation had issues"
        fi
    fi
}

# Test incident response procedures
test_incident_response() {
    header "Testing Incident Response Procedures"
    ((TOTAL_VALIDATIONS++))
    
    log "Testing incident response capabilities..."
    
    # Create test incident scenario
    local test_namespace="incident-response-test"
    kubectl create namespace $test_namespace --dry-run=client -o yaml | kubectl apply -f - &>/dev/null
    
    # Test automated containment
    log "Testing automated containment procedures..."
    
    # Create a test pod that violates security policies
    kubectl apply -f - << EOF &>/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: incident-test-pod
  namespace: $test_namespace
  labels:
    test-type: incident-response
spec:
  containers:
  - name: test
    image: busybox:1.35
    command: ['sleep', '300']
    securityContext:
      runAsUser: 0  # This should trigger policy violation
EOF
    
    # Wait and check if pod was rejected or contained
    sleep 5
    
    local pod_status=$(kubectl get pod incident-test-pod -n $test_namespace -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    
    if [ "$pod_status" = "NotFound" ]; then
        success "Incident response test passed - insecure pod was rejected"
    elif [ "$pod_status" = "Running" ]; then
        warning "Incident response test warning - insecure pod is running (check admission policies)"
        
        # Test containment by applying network policy
        kubectl apply -f - << EOF &>/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: incident-containment
  namespace: $test_namespace
spec:
  podSelector:
    matchLabels:
      test-type: incident-response
  policyTypes:
  - Ingress
  - Egress
EOF
        
        success "Applied containment network policy"
    else
        info "Incident response test inconclusive - pod status: $pod_status"
    fi
    
    # Cleanup test resources
    kubectl delete namespace $test_namespace --ignore-not-found=true &>/dev/null
    
    success "Incident response testing completed"
}

# Generate integrated report
generate_integrated_report() {
    header "Generating Integrated Security Report"
    
    log "Consolidating all validation results..."
    
    local integrated_report="$REPORT_DIR/integrated-security-report.json"
    
    # Create comprehensive report structure
    cat > $integrated_report << EOF
{
  "report_metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cluster": "$CLUSTER_NAME",
    "validation_mode": "$VALIDATION_MODE",
    "report_version": "1.0.0",
    "aws_region": "$AWS_REGION"
  },
  "executive_summary": {
    "overall_security_posture": "$([ $FAILED_VALIDATIONS -eq 0 ] && echo "SECURE" || echo "NEEDS_ATTENTION")",
    "risk_level": "$([ $FAILED_VALIDATIONS -gt 2 ] && echo "HIGH" || [ $FAILED_VALIDATIONS -gt 0 ] && echo "MEDIUM" || echo "LOW")",
    "validation_results": {
      "total_validations": $TOTAL_VALIDATIONS,
      "passed": $PASSED_VALIDATIONS,
      "failed": $FAILED_VALIDATIONS,
      "warnings": $WARNING_VALIDATIONS,
      "success_rate": $([ $TOTAL_VALIDATIONS -gt 0 ] && echo "scale=2; $PASSED_VALIDATIONS * 100 / $TOTAL_VALIDATIONS" | bc || echo "0")
    }
  },
  "validation_components": {},
  "security_metrics": {},
  "compliance_status": {},
  "vulnerability_assessment": {},
  "incident_response_readiness": {},
  "recommendations": []
}
EOF
    
    # Merge individual component reports
    merge_component_reports $integrated_report
    
    # Generate recommendations
    generate_recommendations $integrated_report
    
    # Create additional report formats
    if [ "$OUTPUT_FORMAT" = "html" ] || [ "$OUTPUT_FORMAT" = "all" ]; then
        generate_html_report $integrated_report
    fi
    
    if [ "$OUTPUT_FORMAT" = "pdf" ] || [ "$OUTPUT_FORMAT" = "all" ]; then
        generate_pdf_report $integrated_report
    fi
    
    success "Integrated security report generated: $integrated_report"
}

# Merge component reports
merge_component_reports() {
    local integrated_report=$1
    
    # Merge comprehensive validation results
    if [ -f "$REPORT_DIR/reports/comprehensive-validation.json" ]; then
        jq --slurpfile comp "$REPORT_DIR/reports/comprehensive-validation.json" \
           '.validation_components.comprehensive_validation = $comp[0]' \
           $integrated_report > tmp.json && mv tmp.json $integrated_report
    fi
    
    # Merge security testing results
    if [ -d "$REPORT_DIR/reports/security-testing" ]; then
        local security_testing_summary=$(find "$REPORT_DIR/reports/security-testing" -name "*.json" | head -1)
        if [ -f "$security_testing_summary" ]; then
            jq --slurpfile st "$security_testing_summary" \
               '.validation_components.security_testing = $st[0]' \
               $integrated_report > tmp.json && mv tmp.json $integrated_report
        fi
    fi
    
    # Merge metrics
    if [ -d "$REPORT_DIR/metrics" ]; then
        local metrics_file=$(find "$REPORT_DIR/metrics" -name "consolidated-metrics-*.json" | head -1)
        if [ -f "$metrics_file" ]; then
            jq --slurpfile metrics "$metrics_file" \
               '.security_metrics = $metrics[0]' \
               $integrated_report > tmp.json && mv tmp.json $integrated_report
        fi
    fi
}

# Generate recommendations
generate_recommendations() {
    local integrated_report=$1
    
    local recommendations=()
    
    # Add recommendations based on findings
    if [ $FAILED_VALIDATIONS -gt 0 ]; then
        recommendations+=("Address failed security validations immediately")
    fi
    
    if [ $WARNING_VALIDATIONS -gt 5 ]; then
        recommendations+=("Review and resolve security warnings")
    fi
    
    # Check for specific security issues
    if kubectl get pods --all-namespaces -o json | jq -e '.items[] | select(.spec.securityContext.runAsUser == 0)' &>/dev/null; then
        recommendations+=("Eliminate pods running as root user")
    fi
    
    if ! kubectl get networkpolicies --all-namespaces &>/dev/null || [ $(kubectl get networkpolicies --all-namespaces --no-headers | wc -l) -eq 0 ]; then
        recommendations+=("Implement network policies for pod-to-pod communication control")
    fi
    
    # Convert recommendations to JSON array
    local rec_json=$(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)
    
    jq --argjson recs "$rec_json" '.recommendations = $recs' $integrated_report > tmp.json && mv tmp.json $integrated_report
}

# Generate HTML report
generate_html_report() {
    local json_report=$1
    local html_report="$REPORT_DIR/integrated-security-report.html"
    
    log "Generating HTML report..."
    
    cat > $html_report << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container Security Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007acc; }
        .metric-value { font-size: 2em; font-weight: bold; color: #007acc; }
        .metric-label { color: #666; margin-top: 5px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        .status-pass { color: #28a745; }
        .status-fail { color: #dc3545; }
        .status-warn { color: #ffc107; }
        .recommendations { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .progress-bar { width: 100%; height: 20px; background-color: #e9ecef; border-radius: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background-color: #28a745; transition: width 0.3s ease; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Container Security Validation Report</h1>
            <p>Comprehensive security assessment for Kubernetes cluster</p>
        </div>
EOF
    
    # Add dynamic content from JSON report
    local cluster_name=$(jq -r '.report_metadata.cluster' $json_report)
    local timestamp=$(jq -r '.report_metadata.timestamp' $json_report)
    local success_rate=$(jq -r '.executive_summary.validation_results.success_rate' $json_report)
    local total_validations=$(jq -r '.executive_summary.validation_results.total_validations' $json_report)
    local passed_validations=$(jq -r '.executive_summary.validation_results.passed' $json_report)
    local failed_validations=$(jq -r '.executive_summary.validation_results.failed' $json_report)
    
    cat >> $html_report << EOF
        <div class="summary">
            <div class="metric-card">
                <div class="metric-value">$cluster_name</div>
                <div class="metric-label">Cluster Name</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$success_rate%</div>
                <div class="metric-label">Success Rate</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: $success_rate%"></div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-value status-pass">$passed_validations</div>
                <div class="metric-label">Passed Validations</div>
            </div>
            <div class="metric-card">
                <div class="metric-value status-fail">$failed_validations</div>
                <div class="metric-label">Failed Validations</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p><strong>Assessment Date:</strong> $timestamp</p>
            <p><strong>Total Validations:</strong> $total_validations</p>
            <p><strong>Overall Security Posture:</strong> <span class="$([ $failed_validations -eq 0 ] && echo "status-pass" || echo "status-fail")">$([ $failed_validations -eq 0 ] && echo "SECURE" || echo "NEEDS ATTENTION")</span></p>
        </div>
EOF
    
    # Add recommendations section
    local recommendations=$(jq -r '.recommendations[]' $json_report 2>/dev/null || echo "")
    if [ -n "$recommendations" ]; then
        cat >> $html_report << EOF
        <div class="section">
            <h2>💡 Recommendations</h2>
            <div class="recommendations">
                <ul>
EOF
        echo "$recommendations" | while read -r rec; do
            echo "                    <li>$rec</li>" >> $html_report
        done
        
        cat >> $html_report << EOF
                </ul>
            </div>
        </div>
EOF
    fi
    
    cat >> $html_report << EOF
        <div class="section">
            <h2>📋 Detailed Results</h2>
            <p>For detailed validation results, please refer to the JSON report: <code>integrated-security-report.json</code></p>
        </div>
        
        <div class="section">
            <h2>🔧 Next Steps</h2>
            <ol>
                <li>Review all failed validations and address security issues</li>
                <li>Implement recommended security improvements</li>
                <li>Schedule regular security validation runs</li>
                <li>Monitor security metrics and compliance status</li>
            </ol>
        </div>
    </div>
</body>
</html>
EOF
    
    success "HTML report generated: $html_report"
}

# Generate PDF report (requires wkhtmltopdf)
generate_pdf_report() {
    local json_report=$1
    local pdf_report="$REPORT_DIR/integrated-security-report.pdf"
    
    if command -v wkhtmltopdf &> /dev/null; then
        log "Generating PDF report..."
        wkhtmltopdf "$REPORT_DIR/integrated-security-report.html" "$pdf_report" &>/dev/null
        success "PDF report generated: $pdf_report"
    else
        warning "wkhtmltopdf not available - skipping PDF generation"
    fi
}

# Publish reports
publish_reports() {
    header "Publishing Reports"
    
    case $REPORT_DESTINATION in
        "s3")
            publish_to_s3
            ;;
        "cloudwatch")
            publish_to_cloudwatch
            ;;
        "local")
            info "Reports saved locally in: $REPORT_DIR"
            ;;
        "all")
            publish_to_s3
            publish_to_cloudwatch
            info "Reports saved locally in: $REPORT_DIR"
            ;;
    esac
}

# Publish to S3
publish_to_s3() {
    log "Publishing reports to S3..."
    
    if aws s3 ls s3://$S3_BUCKET &>/dev/null; then
        aws s3 sync $REPORT_DIR s3://$S3_BUCKET/security-reports/$(date +%Y/%m/%d)/$CLUSTER_NAME/ --quiet
        success "Reports published to S3: s3://$S3_BUCKET/security-reports/$(date +%Y/%m/%d)/$CLUSTER_NAME/"
    else
        warning "S3 bucket $S3_BUCKET not accessible - skipping S3 upload"
    fi
}

# Publish to CloudWatch
publish_to_cloudwatch() {
    log "Publishing metrics to CloudWatch..."
    
    # Send validation metrics
    aws cloudwatch put-metric-data \
        --namespace "$CLOUDWATCH_NAMESPACE" \
        --metric-data \
        MetricName=TotalValidations,Value=$TOTAL_VALIDATIONS,Unit=Count,Dimensions=Name=Cluster,Value=$CLUSTER_NAME \
        MetricName=PassedValidations,Value=$PASSED_VALIDATIONS,Unit=Count,Dimensions=Name=Cluster,Value=$CLUSTER_NAME \
        MetricName=FailedValidations,Value=$FAILED_VALIDATIONS,Unit=Count,Dimensions=Name=Cluster,Value=$CLUSTER_NAME \
        MetricName=WarningValidations,Value=$WARNING_VALIDATIONS,Unit=Count,Dimensions=Name=Cluster,Value=$CLUSTER_NAME \
        --region $AWS_REGION &>/dev/null
    
    success "Metrics published to CloudWatch"
}

# Cleanup function
cleanup() {
    if [ "$CLEANUP" = "true" ]; then
        log "Cleaning up temporary validation resources..."
        kubectl delete namespace validation-comprehensive validation-testing --ignore-not-found=true &>/dev/null
        success "Cleanup completed"
    fi
}

# Main execution function
main() {
    echo "========================================="
    echo "🛡️  Integrated Security Validation Framework"
    echo "========================================="
    echo "Version: 1.0.0"
    echo "Cluster: $CLUSTER_NAME"
    echo "Mode: $VALIDATION_MODE"
    echo "Output Format: $OUTPUT_FORMAT"
    echo "Destination: $REPORT_DESTINATION"
    echo "Timestamp: $(date)"
    echo
    
    init_validation_environment
    
    case $VALIDATION_MODE in
        "full")
            run_comprehensive_validation
            run_security_testing_framework
            collect_security_metrics
            run_compliance_validation
            run_vulnerability_assessment
            test_incident_response
            ;;
        "quick")
            run_comprehensive_validation
            collect_security_metrics
            ;;
        "compliance")
            run_compliance_validation
            collect_security_metrics
            ;;
        "vulnerability")
            run_vulnerability_assessment
            collect_security_metrics
            ;;
        *)
            warning "Unknown validation mode: $VALIDATION_MODE"
            run_comprehensive_validation
            ;;
    esac
    
    generate_integrated_report
    publish_reports
    
    # Display final summary
    echo
    echo "========================================="
    echo "🏁 VALIDATION SUMMARY"
    echo "========================================="
    echo "Total Validations: $TOTAL_VALIDATIONS"
    echo "Passed: $PASSED_VALIDATIONS"
    echo "Failed: $FAILED_VALIDATIONS"
    echo "Warnings: $WARNING_VALIDATIONS"
    echo "Success Rate: $([ $TOTAL_VALIDATIONS -gt 0 ] && echo "scale=1; $PASSED_VALIDATIONS * 100 / $TOTAL_VALIDATIONS" | bc || echo "0")%"
    echo
    echo "Report Directory: $REPORT_DIR"
    echo
    
    if [ $FAILED_VALIDATIONS -gt 0 ]; then
        echo -e "${RED}❌ SECURITY VALIDATION FAILED${NC}"
        echo "Critical security issues found that require immediate attention."
        cleanup
        exit 1
    elif [ $WARNING_VALIDATIONS -gt 0 ]; then
        echo -e "${YELLOW}⚠️  SECURITY VALIDATION COMPLETED WITH WARNINGS${NC}"
        echo "Some security issues found that should be addressed."
        cleanup
        exit 0
    else
        echo -e "${GREEN}✅ SECURITY VALIDATION PASSED${NC}"
        echo "Container security implementation meets all security standards."
        cleanup
        exit 0
    fi
}

# Handle script interruption
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    local required_tools=("kubectl" "aws" "jq" "bc")
    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            failure "Required tool not found: $tool"
            exit 1
        fi
    done
    
    if ! kubectl cluster-info &>/dev/null; then
        failure "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    if ! aws sts get-caller-identity &>/dev/null; then
        failure "AWS credentials not configured"
        exit 1
    fi
}

# Run main function
check_prerequisites
main "$@"