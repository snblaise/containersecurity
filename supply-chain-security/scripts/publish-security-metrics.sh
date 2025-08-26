#!/bin/bash

# Script to publish security metrics to CloudWatch from CodeBuild
# This script is called from the buildspec to record security scan results

set -e

# Function to publish CloudWatch metrics
publish_metric() {
    local metric_name="$1"
    local value="$2"
    local unit="${3:-Count}"
    local namespace="SupplyChainSecurity"
    
    aws cloudwatch put-metric-data \
        --namespace "$namespace" \
        --metric-data MetricName="$metric_name",Value="$value",Unit="$unit",Dimensions=ProjectName="$PROJECT_NAME"
    
    echo "Published metric: $metric_name = $value"
}

# Function to publish security scan metrics
publish_security_metrics() {
    local sast_file="$1"
    local sca_file="$2"
    local image_scan_file="$3"
    
    echo "Publishing security metrics to CloudWatch..."
    
    # Parse SAST results if file exists
    if [[ -f "$sast_file" ]]; then
        local critical_sast=$(jq '.results | map(select(.extra.severity == "ERROR")) | length' "$sast_file" 2>/dev/null || echo "0")
        local high_sast=$(jq '.results | map(select(.extra.severity == "WARNING")) | length' "$sast_file" 2>/dev/null || echo "0")
        
        publish_metric "SASTCriticalIssues" "$critical_sast"
        publish_metric "SASTHighIssues" "$high_sast"
        publish_metric "SASTIssues" $((critical_sast + high_sast))
        
        echo "SAST metrics published: Critical=$critical_sast, High=$high_sast"
    fi
    
    # Parse SCA results if file exists
    if [[ -f "$sca_file" ]]; then
        local critical_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$sca_file" 2>/dev/null || echo "0")
        local high_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$sca_file" 2>/dev/null || echo "0")
        local medium_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$sca_file" 2>/dev/null || echo "0")
        
        publish_metric "CriticalVulnerabilities" "$critical_sca"
        publish_metric "HighVulnerabilities" "$high_sca"
        publish_metric "MediumVulnerabilities" "$medium_sca"
        publish_metric "SCAIssues" $((critical_sca + high_sca + medium_sca))
        
        echo "SCA metrics published: Critical=$critical_sca, High=$high_sca, Medium=$medium_sca"
    fi
    
    # Parse image scan results if file exists
    if [[ -f "$image_scan_file" ]]; then
        local critical_image=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$image_scan_file" 2>/dev/null || echo "0")
        local high_image=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$image_scan_file" 2>/dev/null || echo "0")
        
        publish_metric "ImageCriticalVulnerabilities" "$critical_image"
        publish_metric "ImageHighVulnerabilities" "$high_image"
        publish_metric "ImagesScanned" "1"
        
        echo "Image scan metrics published: Critical=$critical_image, High=$high_image"
    fi
    
    # Publish build status metrics
    if [[ "$CODEBUILD_BUILD_SUCCEEDING" == "1" ]]; then
        publish_metric "BuildsPassed" "1"
    else
        publish_metric "BuildsFailed" "1"
        publish_metric "BuildsBlocked" "1"
    fi
    
    # Publish timing metrics
    if [[ -n "$BUILD_START_TIME" ]]; then
        local build_duration=$(($(date +%s) - BUILD_START_TIME))
        publish_metric "BuildDuration" "$build_duration" "Seconds"
    fi
}

# Function to check security gate thresholds and publish alerts
check_security_gates() {
    local sast_file="$1"
    local sca_file="$2"
    local max_critical="${MAX_CRITICAL_VULNERABILITIES:-0}"
    local max_high="${MAX_HIGH_VULNERABILITIES:-5}"
    local max_medium="${MAX_MEDIUM_VULNERABILITIES:-20}"
    
    local gate_failures=0
    
    echo "Checking security gate thresholds..."
    
    # Check SAST thresholds
    if [[ -f "$sast_file" ]]; then
        local critical_sast=$(jq '.results | map(select(.extra.severity == "ERROR")) | length' "$sast_file" 2>/dev/null || echo "0")
        if [[ "$critical_sast" -gt 0 ]]; then
            echo "SECURITY GATE FAILURE: $critical_sast critical SAST issues detected"
            publish_metric "SASTGateFailures" "1"
            ((gate_failures++))
        fi
    fi
    
    # Check SCA thresholds
    if [[ -f "$sca_file" ]]; then
        local critical_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$sca_file" 2>/dev/null || echo "0")
        local high_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$sca_file" 2>/dev/null || echo "0")
        local medium_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$sca_file" 2>/dev/null || echo "0")
        
        if [[ "$critical_sca" -gt "$max_critical" ]]; then
            echo "SECURITY GATE FAILURE: $critical_sca critical vulnerabilities exceed threshold of $max_critical"
            publish_metric "CriticalVulnGateFailures" "1"
            ((gate_failures++))
        fi
        
        if [[ "$high_sca" -gt "$max_high" ]]; then
            echo "SECURITY GATE FAILURE: $high_sca high vulnerabilities exceed threshold of $max_high"
            publish_metric "HighVulnGateFailures" "1"
            ((gate_failures++))
        fi
        
        if [[ "$medium_sca" -gt "$max_medium" ]]; then
            echo "SECURITY GATE FAILURE: $medium_sca medium vulnerabilities exceed threshold of $max_medium"
            publish_metric "MediumVulnGateFailures" "1"
            ((gate_failures++))
        fi
    fi
    
    # Publish total gate failures
    publish_metric "SecurityGateFailures" "$gate_failures"
    
    return $gate_failures
}

# Function to generate security report
generate_security_report() {
    local output_file="$1"
    local sast_file="$2"
    local sca_file="$3"
    local image_scan_file="$4"
    
    echo "Generating security report..."
    
    cat > "$output_file" << EOF
# Security Scan Report

**Build ID:** $CODEBUILD_BUILD_ID
**Source Version:** $CODEBUILD_RESOLVED_SOURCE_VERSION
**Scan Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Summary

EOF

    # Add SAST summary
    if [[ -f "$sast_file" ]]; then
        local critical_sast=$(jq '.results | map(select(.extra.severity == "ERROR")) | length' "$sast_file" 2>/dev/null || echo "0")
        local high_sast=$(jq '.results | map(select(.extra.severity == "WARNING")) | length' "$sast_file" 2>/dev/null || echo "0")
        
        cat >> "$output_file" << EOF
### Static Application Security Testing (SAST)
- Critical Issues: $critical_sast
- High Issues: $high_sast

EOF
    fi
    
    # Add SCA summary
    if [[ -f "$sca_file" ]]; then
        local critical_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$sca_file" 2>/dev/null || echo "0")
        local high_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$sca_file" 2>/dev/null || echo "0")
        local medium_sca=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$sca_file" 2>/dev/null || echo "0")
        
        cat >> "$output_file" << EOF
### Software Composition Analysis (SCA)
- Critical Vulnerabilities: $critical_sca
- High Vulnerabilities: $high_sca
- Medium Vulnerabilities: $medium_sca

EOF
    fi
    
    # Add image scan summary
    if [[ -f "$image_scan_file" ]]; then
        local critical_image=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$image_scan_file" 2>/dev/null || echo "0")
        local high_image=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$image_scan_file" 2>/dev/null || echo "0")
        
        cat >> "$output_file" << EOF
### Container Image Scan
- Critical Vulnerabilities: $critical_image
- High Vulnerabilities: $high_image

EOF
    fi
    
    cat >> "$output_file" << EOF
## Security Gate Status

EOF
    
    if check_security_gates "$sast_file" "$sca_file"; then
        echo "✅ All security gates passed" >> "$output_file"
    else
        echo "❌ Security gates failed - build blocked" >> "$output_file"
    fi
    
    echo "Security report generated: $output_file"
}

# Main execution
main() {
    local command="${1:-publish}"
    
    case "$command" in
        "publish")
            publish_security_metrics \
                "${SAST_RESULTS_FILE:-/tmp/sast-results.json}" \
                "${SCA_RESULTS_FILE:-/tmp/sca-results.json}" \
                "${IMAGE_SCAN_RESULTS_FILE:-/tmp/image-scan-results.json}"
            ;;
        "check")
            check_security_gates \
                "${SAST_RESULTS_FILE:-/tmp/sast-results.json}" \
                "${SCA_RESULTS_FILE:-/tmp/sca-results.json}"
            ;;
        "report")
            generate_security_report \
                "${SECURITY_REPORT_FILE:-/tmp/security-report.md}" \
                "${SAST_RESULTS_FILE:-/tmp/sast-results.json}" \
                "${SCA_RESULTS_FILE:-/tmp/sca-results.json}" \
                "${IMAGE_SCAN_RESULTS_FILE:-/tmp/image-scan-results.json}"
            ;;
        *)
            echo "Usage: $0 {publish|check|report}"
            echo "  publish - Publish security metrics to CloudWatch"
            echo "  check   - Check security gate thresholds"
            echo "  report  - Generate security report"
            exit 1
            ;;
    esac
}

# Set default project name if not provided
PROJECT_NAME="${PROJECT_NAME:-secure-container}"
BUILD_START_TIME="${BUILD_START_TIME:-$(date +%s)}"

# Execute main function
main "$@"