#!/bin/bash

# Continuous Compliance Monitoring Script
# This script orchestrates comprehensive compliance monitoring across all security controls
# Requirements: 4.2, 4.5

set -euo pipefail

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-}"
MONITORING_INTERVAL="${MONITORING_INTERVAL:-3600}"  # 1 hour default
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/compliance-reports}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
EMAIL_RECIPIENTS="${EMAIL_RECIPIENTS:-}"
COMPLIANCE_THRESHOLD="${COMPLIANCE_THRESHOLD:-85}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Continuous Compliance Monitoring for Container Security

OPTIONS:
    -c, --cluster CLUSTER_NAME        EKS cluster name (required)
    -i, --interval SECONDS           Monitoring interval in seconds (default: 3600)
    -o, --output-dir DIRECTORY       Output directory for reports (default: /tmp/compliance-reports)
    -w, --webhook URL                Webhook URL for notifications
    -e, --email RECIPIENTS           Comma-separated email recipients
    -t, --threshold PERCENTAGE       Compliance threshold percentage (default: 85)
    --verbose                        Enable verbose output
    --daemon                         Run as daemon process
    --once                          Run once and exit
    -h, --help                       Show this help message

EXAMPLES:
    $0 --cluster production-eks --once
    $0 -c staging-eks --daemon --interval 1800
    $0 --cluster prod-eks --webhook https://hooks.slack.com/... --email admin@company.com

ENVIRONMENT VARIABLES:
    CLUSTER_NAME                     EKS cluster name
    MONITORING_INTERVAL              Monitoring interval in seconds
    OUTPUT_DIR                       Output directory for reports
    WEBHOOK_URL                      Webhook URL for notifications
    EMAIL_RECIPIENTS                 Comma-separated email recipients
    COMPLIANCE_THRESHOLD             Compliance threshold percentage

EOF
}

# Parse command line arguments
parse_args() {
    local daemon_mode=false
    local run_once=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--cluster)
                CLUSTER_NAME="$2"
                shift 2
                ;;
            -i|--interval)
                MONITORING_INTERVAL="$2"
                shift 2
                ;;
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -w|--webhook)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            -e|--email)
                EMAIL_RECIPIENTS="$2"
                shift 2
                ;;
            -t|--threshold)
                COMPLIANCE_THRESHOLD="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --daemon)
                daemon_mode=true
                shift
                ;;
            --once)
                run_once=true
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

    if [[ "$daemon_mode" == true && "$run_once" == true ]]; then
        log_error "Cannot specify both --daemon and --once"
        exit 1
    fi

    export DAEMON_MODE="$daemon_mode"
    export RUN_ONCE="$run_once"
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Check required tools
    command -v kubectl >/dev/null 2>&1 || missing_tools+=("kubectl")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")
    command -v aws >/dev/null 2>&1 || missing_tools+=("aws")
    command -v curl >/dev/null 2>&1 || missing_tools+=("curl")

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    # Check for compliance scripts
    if [[ ! -f "$script_dir/security-policy-compliance.sh" ]]; then
        log_error "Security policy compliance script not found"
        exit 1
    fi

    if [[ ! -f "$script_dir/cis-kubernetes-benchmark.sh" ]]; then
        log_error "CIS Kubernetes benchmark script not found"
        exit 1
    fi

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Check AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        log_error "AWS credentials not configured"
        exit 1
    fi
}

# Initialize monitoring
init_monitoring() {
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    
    export REPORT_TIMESTAMP="$timestamp"
    export SECURITY_REPORT="$OUTPUT_DIR/security-compliance-$timestamp.json"
    export CIS_REPORT="$OUTPUT_DIR/cis-benchmark-$timestamp.json"
    export COMBINED_REPORT="$OUTPUT_DIR/combined-compliance-$timestamp.json"
    export SUMMARY_REPORT="$OUTPUT_DIR/compliance-summary-$timestamp.json"

    log_info "Initializing compliance monitoring for cluster: $CLUSTER_NAME"
    log_info "Reports will be saved to: $OUTPUT_DIR"
}

# Run security policy compliance check
run_security_compliance() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    log_info "Running security policy compliance check..."
    
    if "$script_dir/security-policy-compliance.sh" \
        --cluster "$CLUSTER_NAME" \
        --format json \
        --threshold "$COMPLIANCE_THRESHOLD" > "$SECURITY_REPORT" 2>/dev/null; then
        log_success "Security policy compliance check completed"
        return 0
    else
        log_warn "Security policy compliance check failed or found issues"
        return 1
    fi
}

# Run CIS Kubernetes benchmark
run_cis_benchmark() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    log_info "Running CIS Kubernetes benchmark..."
    
    if "$script_dir/cis-kubernetes-benchmark.sh" \
        --cluster "$CLUSTER_NAME" \
        --format json > "$CIS_REPORT" 2>/dev/null; then
        log_success "CIS Kubernetes benchmark completed"
        return 0
    else
        log_warn "CIS Kubernetes benchmark failed or found issues"
        return 1
    fi
}

# Check AWS Config compliance
check_aws_config_compliance() {
    log_info "Checking AWS Config compliance..."
    
    local config_rules
    config_rules=$(aws configservice describe-config-rules \
        --query "ConfigRules[?contains(ConfigRuleName, '$CLUSTER_NAME')].ConfigRuleName" \
        --output text 2>/dev/null || echo "")

    if [[ -z "$config_rules" ]]; then
        log_warn "No AWS Config rules found for cluster: $CLUSTER_NAME"
        return 1
    fi

    local compliance_results=()
    local total_rules=0
    local compliant_rules=0

    while IFS= read -r rule_name; do
        if [[ -n "$rule_name" ]]; then
            ((total_rules++))
            local compliance_status
            compliance_status=$(aws configservice get-compliance-details-by-config-rule \
                --config-rule-name "$rule_name" \
                --query 'EvaluationResults[0].ComplianceType' \
                --output text 2>/dev/null || echo "INSUFFICIENT_DATA")
            
            if [[ "$compliance_status" == "COMPLIANT" ]]; then
                ((compliant_rules++))
            fi

            compliance_results+=("{\"rule_name\": \"$rule_name\", \"status\": \"$compliance_status\"}")
            
            [[ "$VERBOSE" == true ]] && log_info "Config rule $rule_name: $compliance_status"
        fi
    done <<< "$config_rules"

    local compliance_percentage=0
    if [[ $total_rules -gt 0 ]]; then
        compliance_percentage=$((compliant_rules * 100 / total_rules))
    fi

    # Create AWS Config compliance report
    local config_report
    config_report=$(jq -n \
        --arg cluster "$CLUSTER_NAME" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson total "$total_rules" \
        --argjson compliant "$compliant_rules" \
        --argjson percentage "$compliance_percentage" \
        --argjson rules "$(printf '%s\n' "${compliance_results[@]}" | jq -s '.')" \
        '{
            cluster_name: $cluster,
            timestamp: $timestamp,
            aws_config: {
                total_rules: $total,
                compliant_rules: $compliant,
                compliance_percentage: $percentage,
                rules: $rules
            }
        }')

    echo "$config_report" > "$OUTPUT_DIR/aws-config-$REPORT_TIMESTAMP.json"

    if [[ $compliance_percentage -ge $COMPLIANCE_THRESHOLD ]]; then
        log_success "AWS Config compliance: $compliance_percentage% ($compliant_rules/$total_rules rules)"
        return 0
    else
        log_warn "AWS Config compliance below threshold: $compliance_percentage% ($compliant_rules/$total_rules rules)"
        return 1
    fi
}

# Check GuardDuty findings
check_guardduty_findings() {
    log_info "Checking GuardDuty findings..."
    
    local detector_id
    detector_id=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")

    if [[ -z "$detector_id" || "$detector_id" == "None" ]]; then
        log_warn "GuardDuty detector not found"
        return 1
    fi

    # Get findings from last 24 hours
    local start_time
    start_time=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
    
    local findings
    findings=$(aws guardduty list-findings \
        --detector-id "$detector_id" \
        --finding-criteria "{\"UpdatedAt\":{\"GreaterThan\":\"$start_time\"}}" \
        --query 'FindingIds' \
        --output json 2>/dev/null || echo "[]")

    local finding_count
    finding_count=$(echo "$findings" | jq 'length')

    local high_severity_count=0
    local critical_severity_count=0

    if [[ $finding_count -gt 0 ]]; then
        local finding_details
        finding_details=$(aws guardduty get-findings \
            --detector-id "$detector_id" \
            --finding-ids "$(echo "$findings" | jq -r '.[]')" \
            --query 'Findings[].{Id:Id,Severity:Severity,Type:Type,Title:Title}' \
            --output json 2>/dev/null || echo "[]")

        high_severity_count=$(echo "$finding_details" | jq '[.[] | select(.Severity >= 7.0 and .Severity < 8.5)] | length')
        critical_severity_count=$(echo "$finding_details" | jq '[.[] | select(.Severity >= 8.5)] | length')
    fi

    # Create GuardDuty report
    local guardduty_report
    guardduty_report=$(jq -n \
        --arg cluster "$CLUSTER_NAME" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson total "$finding_count" \
        --argjson high "$high_severity_count" \
        --argjson critical "$critical_severity_count" \
        '{
            cluster_name: $cluster,
            timestamp: $timestamp,
            guardduty: {
                total_findings_24h: $total,
                high_severity_findings: $high,
                critical_severity_findings: $critical
            }
        }')

    echo "$guardduty_report" > "$OUTPUT_DIR/guardduty-$REPORT_TIMESTAMP.json"

    if [[ $critical_severity_count -eq 0 && $high_severity_count -le 5 ]]; then
        log_success "GuardDuty findings within acceptable limits: $finding_count total, $high_severity_count high, $critical_severity_count critical"
        return 0
    else
        log_warn "GuardDuty findings require attention: $finding_count total, $high_severity_count high, $critical_severity_count critical"
        return 1
    fi
}

# Combine all compliance reports
combine_reports() {
    log_info "Combining compliance reports..."

    local security_data="{}"
    local cis_data="{}"
    local config_data="{}"
    local guardduty_data="{}"

    # Load security compliance data
    if [[ -f "$SECURITY_REPORT" ]]; then
        security_data=$(cat "$SECURITY_REPORT")
    fi

    # Load CIS benchmark data
    if [[ -f "$CIS_REPORT" ]]; then
        cis_data=$(cat "$CIS_REPORT")
    fi

    # Load AWS Config data
    if [[ -f "$OUTPUT_DIR/aws-config-$REPORT_TIMESTAMP.json" ]]; then
        config_data=$(cat "$OUTPUT_DIR/aws-config-$REPORT_TIMESTAMP.json")
    fi

    # Load GuardDuty data
    if [[ -f "$OUTPUT_DIR/guardduty-$REPORT_TIMESTAMP.json" ]]; then
        guardduty_data=$(cat "$OUTPUT_DIR/guardduty-$REPORT_TIMESTAMP.json")
    fi

    # Combine all reports
    local combined_report
    combined_report=$(jq -n \
        --arg cluster "$CLUSTER_NAME" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson security "$security_data" \
        --argjson cis "$cis_data" \
        --argjson config "$config_data" \
        --argjson guardduty "$guardduty_data" \
        '{
            cluster_name: $cluster,
            timestamp: $timestamp,
            security_compliance: $security,
            cis_benchmark: $cis,
            aws_config: $config.aws_config // {},
            guardduty: $guardduty.guardduty // {}
        }')

    echo "$combined_report" > "$COMBINED_REPORT"

    # Create summary report
    create_summary_report "$combined_report"
}

# Create summary report
create_summary_report() {
    local combined_data="$1"
    
    log_info "Creating compliance summary..."

    local summary
    summary=$(echo "$combined_data" | jq '{
        cluster_name: .cluster_name,
        timestamp: .timestamp,
        overall_compliance: {
            security_policy: {
                status: .security_compliance.summary.overall_status // "UNKNOWN",
                percentage: .security_compliance.summary.compliance_percentage // 0,
                passed_checks: .security_compliance.summary.passed_checks // 0,
                failed_checks: .security_compliance.summary.failed_checks // 0
            },
            cis_benchmark: {
                score: .cis_benchmark.summary.compliance_score // 0,
                passed_controls: .cis_benchmark.summary.passed_controls // 0,
                failed_controls: .cis_benchmark.summary.failed_controls // 0
            },
            aws_config: {
                percentage: .aws_config.compliance_percentage // 0,
                compliant_rules: .aws_config.compliant_rules // 0,
                total_rules: .aws_config.total_rules // 0
            },
            guardduty: {
                total_findings: .guardduty.total_findings_24h // 0,
                high_severity: .guardduty.high_severity_findings // 0,
                critical_severity: .guardduty.critical_severity_findings // 0
            }
        }
    }')

    echo "$summary" > "$SUMMARY_REPORT"

    # Calculate overall compliance score
    local security_score cis_score config_score overall_score
    security_score=$(echo "$summary" | jq '.overall_compliance.security_policy.percentage')
    cis_score=$(echo "$summary" | jq '.overall_compliance.cis_benchmark.score')
    config_score=$(echo "$summary" | jq '.overall_compliance.aws_config.percentage')
    
    overall_score=$(echo "$security_score $cis_score $config_score" | awk '{print int(($1 + $2 + $3) / 3)}')

    # Update summary with overall score
    local final_summary
    final_summary=$(echo "$summary" | jq --argjson score "$overall_score" '.overall_compliance.overall_score = $score')
    echo "$final_summary" > "$SUMMARY_REPORT"

    log_info "Overall compliance score: $overall_score%"
    
    return "$overall_score"
}

# Send notifications
send_notifications() {
    local overall_score="$1"
    local summary_data
    summary_data=$(cat "$SUMMARY_REPORT")

    # Determine notification level
    local notification_level="INFO"
    if [[ $overall_score -lt $COMPLIANCE_THRESHOLD ]]; then
        notification_level="WARNING"
    fi

    local critical_findings
    critical_findings=$(echo "$summary_data" | jq '.overall_compliance.guardduty.critical_severity')
    
    if [[ $critical_findings -gt 0 ]]; then
        notification_level="CRITICAL"
    fi

    # Send webhook notification
    if [[ -n "$WEBHOOK_URL" ]]; then
        send_webhook_notification "$notification_level" "$overall_score" "$summary_data"
    fi

    # Send email notification
    if [[ -n "$EMAIL_RECIPIENTS" ]]; then
        send_email_notification "$notification_level" "$overall_score" "$summary_data"
    fi
}

# Send webhook notification
send_webhook_notification() {
    local level="$1"
    local score="$2"
    local data="$3"

    log_info "Sending webhook notification..."

    local color="#36a64f"  # Green
    if [[ "$level" == "WARNING" ]]; then
        color="#ff9900"  # Orange
    elif [[ "$level" == "CRITICAL" ]]; then
        color="#ff0000"  # Red
    fi

    local payload
    payload=$(jq -n \
        --arg cluster "$CLUSTER_NAME" \
        --arg level "$level" \
        --argjson score "$score" \
        --arg color "$color" \
        --arg timestamp "$(date '+%Y-%m-%d %H:%M:%S UTC')" \
        '{
            text: "Container Security Compliance Report",
            attachments: [{
                color: $color,
                title: "Cluster: \($cluster)",
                fields: [
                    {
                        title: "Overall Compliance Score",
                        value: "\($score)%",
                        short: true
                    },
                    {
                        title: "Status",
                        value: $level,
                        short: true
                    },
                    {
                        title: "Timestamp",
                        value: $timestamp,
                        short: false
                    }
                ]
            }]
        }')

    if curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$WEBHOOK_URL" >/dev/null; then
        log_success "Webhook notification sent"
    else
        log_error "Failed to send webhook notification"
    fi
}

# Send email notification
send_email_notification() {
    local level="$1"
    local score="$2"
    local data="$3"

    log_info "Sending email notification..."

    local subject="[$level] Container Security Compliance Report - $CLUSTER_NAME"
    local body
    body=$(cat << EOF
Container Security Compliance Report

Cluster: $CLUSTER_NAME
Timestamp: $(date '+%Y-%m-%d %H:%M:%S UTC')
Overall Compliance Score: $score%
Status: $level

Security Policy Compliance: $(echo "$data" | jq -r '.overall_compliance.security_policy.percentage')%
CIS Benchmark Score: $(echo "$data" | jq -r '.overall_compliance.cis_benchmark.score')%
AWS Config Compliance: $(echo "$data" | jq -r '.overall_compliance.aws_config.percentage')%

GuardDuty Findings (24h):
- Total: $(echo "$data" | jq -r '.overall_compliance.guardduty.total_findings')
- High Severity: $(echo "$data" | jq -r '.overall_compliance.guardduty.high_severity')
- Critical Severity: $(echo "$data" | jq -r '.overall_compliance.guardduty.critical_severity')

Detailed reports are available at: $OUTPUT_DIR

EOF
)

    # Use AWS SES to send email (requires AWS CLI and SES configuration)
    if command -v aws >/dev/null 2>&1; then
        IFS=',' read -ra recipients <<< "$EMAIL_RECIPIENTS"
        for recipient in "${recipients[@]}"; do
            if aws ses send-email \
                --source "noreply@$(aws sts get-caller-identity --query Account --output text).amazonaws.com" \
                --destination "ToAddresses=$recipient" \
                --message "Subject={Data=\"$subject\"},Body={Text={Data=\"$body\"}}" >/dev/null 2>&1; then
                log_success "Email sent to $recipient"
            else
                log_error "Failed to send email to $recipient"
            fi
        done
    else
        log_warn "AWS CLI not available for email notifications"
    fi
}

# Run single compliance check
run_compliance_check() {
    local start_time
    start_time=$(date +%s)
    
    log_info "Starting compliance check for cluster: $CLUSTER_NAME"

    # Initialize monitoring
    init_monitoring

    # Run all compliance checks
    local security_result=0
    local cis_result=0
    local config_result=0
    local guardduty_result=0

    run_security_compliance || security_result=$?
    run_cis_benchmark || cis_result=$?
    check_aws_config_compliance || config_result=$?
    check_guardduty_findings || guardduty_result=$?

    # Combine reports and create summary
    combine_reports
    local overall_score
    create_summary_report "$(cat "$COMBINED_REPORT")"
    overall_score=$?

    # Send notifications
    send_notifications "$overall_score"

    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - start_time))

    log_info "Compliance check completed in ${duration}s with overall score: $overall_score%"

    # Return appropriate exit code
    if [[ $overall_score -ge $COMPLIANCE_THRESHOLD ]]; then
        return 0
    else
        return 1
    fi
}

# Daemon mode
run_daemon() {
    log_info "Starting compliance monitoring daemon (interval: ${MONITORING_INTERVAL}s)"
    
    while true; do
        if run_compliance_check; then
            log_success "Compliance check passed"
        else
            log_warn "Compliance check failed or found issues"
        fi
        
        log_info "Sleeping for $MONITORING_INTERVAL seconds..."
        sleep "$MONITORING_INTERVAL"
    done
}

# Signal handlers for daemon mode
cleanup() {
    log_info "Shutting down compliance monitoring daemon"
    exit 0
}

trap cleanup SIGTERM SIGINT

# Main execution
main() {
    parse_args "$@"
    check_prerequisites

    if [[ "$DAEMON_MODE" == true ]]; then
        run_daemon
    else
        run_compliance_check
    fi
}

# Run main function
main "$@"