#!/bin/bash

# Emergency deployment approval script for supply chain security
# Provides controlled mechanism for emergency deployments with proper audit trails

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/../admission-policies/emergency-approval-config.yaml}"
NOTIFICATION_WEBHOOK="${NOTIFICATION_WEBHOOK:-}"
SLACK_CHANNEL="${SLACK_CHANNEL:-#security-alerts}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
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

# Function to validate approver
validate_approver() {
    local approver="$1"
    local scenario="$2"
    
    log "Validating approver: $approver for scenario: $scenario"
    
    # Check if approver is in authorized list
    if ! grep -q "$approver" "$CONFIG_FILE" 2>/dev/null; then
        error "Approver $approver is not in the authorized list"
        return 1
    fi
    
    # Get approver's approval level
    local approval_level=$(yq eval ".approvers[] | select(.email == \"$approver\") | .approval_level" "$CONFIG_FILE" 2>/dev/null || echo "")
    
    if [[ -z "$approval_level" ]]; then
        error "Could not determine approval level for $approver"
        return 1
    fi
    
    # Get required level for scenario
    local required_level=$(yq eval ".scenarios[] | select(.type == \"$scenario\") | .required_level" "$CONFIG_FILE" 2>/dev/null || echo "medium")
    
    log "Approver level: $approval_level, Required level: $required_level"
    
    # Simple level validation (in real implementation, use proper hierarchy)
    case "$required_level" in
        "critical")
            if [[ "$approval_level" != "critical" ]]; then
                error "Scenario '$scenario' requires critical approval level, but approver has '$approval_level'"
                return 1
            fi
            ;;
        "high")
            if [[ "$approval_level" != "critical" && "$approval_level" != "high" ]]; then
                error "Scenario '$scenario' requires high or critical approval level, but approver has '$approval_level'"
                return 1
            fi
            ;;
        "medium")
            if [[ "$approval_level" == "low" ]]; then
                error "Scenario '$scenario' requires medium or higher approval level, but approver has '$approval_level'"
                return 1
            fi
            ;;
    esac
    
    success "Approver validation passed"
    return 0
}

# Function to calculate expiry time
calculate_expiry() {
    local approver="$1"
    local scenario="$2"
    local duration="$3"
    
    # Get max duration for approver
    local max_duration=$(yq eval ".approvers[] | select(.email == \"$approver\") | .max_duration" "$CONFIG_FILE" 2>/dev/null || echo "8h")
    
    # Get max duration for scenario
    local scenario_max=$(yq eval ".scenarios[] | select(.type == \"$scenario\") | .max_duration" "$CONFIG_FILE" 2>/dev/null || echo "12h")
    
    # Use the minimum of requested, approver max, and scenario max
    local final_duration="$duration"
    
    # Convert durations to minutes for comparison (simplified)
    local duration_minutes=$(echo "$duration" | sed 's/h/*60+/g; s/m/+/g; s/+$//' | bc 2>/dev/null || echo "480")
    local max_minutes=$(echo "$max_duration" | sed 's/h/*60+/g; s/m/+/g; s/+$//' | bc 2>/dev/null || echo "480")
    local scenario_minutes=$(echo "$scenario_max" | sed 's/h/*60+/g; s/m/+/g; s/+$//' | bc 2>/dev/null || echo "720")
    
    # Use the minimum duration
    local min_minutes=$duration_minutes
    if [[ $max_minutes -lt $min_minutes ]]; then
        min_minutes=$max_minutes
        final_duration="$max_duration"
    fi
    if [[ $scenario_minutes -lt $min_minutes ]]; then
        min_minutes=$scenario_minutes
        final_duration="$scenario_max"
    fi
    
    # Calculate expiry timestamp
    local expiry=$(date -u -d "+$final_duration" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v "+${final_duration}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
    
    echo "$expiry"
}

# Function to send notifications
send_notification() {
    local message="$1"
    local severity="${2:-warning}"
    
    log "Sending notification: $message"
    
    # Send to Slack if webhook is configured
    if [[ -n "$NOTIFICATION_WEBHOOK" ]]; then
        local color="warning"
        case "$severity" in
            "critical") color="danger" ;;
            "high") color="warning" ;;
            "medium") color="good" ;;
        esac
        
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"channel\":\"$SLACK_CHANNEL\",\"text\":\"🚨 Emergency Deployment Alert\",\"attachments\":[{\"color\":\"$color\",\"text\":\"$message\"}]}" \
            "$NOTIFICATION_WEBHOOK" 2>/dev/null || warning "Failed to send Slack notification"
    fi
    
    # Log to system log
    logger -t "emergency-deployment" "$message"
}

# Function to create emergency deployment
create_emergency_deployment() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace="$3"
    local approver="$4"
    local justification="$5"
    local incident_id="$6"
    local scenario="$7"
    local duration="$8"
    
    log "Creating emergency deployment approval..."
    
    # Validate inputs
    if [[ -z "$resource_type" || -z "$resource_name" || -z "$namespace" || -z "$approver" || -z "$justification" || -z "$incident_id" ]]; then
        error "Missing required parameters"
        echo "Usage: create_emergency_deployment <resource_type> <resource_name> <namespace> <approver> <justification> <incident_id> [scenario] [duration]"
        return 1
    fi
    
    # Set defaults
    scenario="${scenario:-production-outage}"
    duration="${duration:-4h}"
    
    # Validate approver
    if ! validate_approver "$approver" "$scenario"; then
        return 1
    fi
    
    # Calculate expiry
    local expiry=$(calculate_expiry "$approver" "$scenario" "$duration")
    
    log "Emergency deployment details:"
    log "  Resource: $resource_type/$resource_name in namespace $namespace"
    log "  Approver: $approver"
    log "  Scenario: $scenario"
    log "  Duration: $duration"
    log "  Expiry: $expiry"
    log "  Incident ID: $incident_id"
    log "  Justification: $justification"
    
    # Apply annotations to the resource
    local annotations=(
        "security.policy/emergency-override=true"
        "security.policy/approver=$approver"
        "security.policy/justification=$justification"
        "security.policy/incident-id=$incident_id"
        "security.policy/scenario=$scenario"
        "security.policy/expiry=$expiry"
        "security.policy/approved-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    )
    
    log "Applying emergency override annotations..."
    
    for annotation in "${annotations[@]}"; do
        if ! kubectl annotate "$resource_type" "$resource_name" -n "$namespace" "$annotation" --overwrite; then
            error "Failed to apply annotation: $annotation"
            return 1
        fi
    done
    
    success "Emergency deployment approval created successfully"
    
    # Send notification
    local notification_message="Emergency deployment approved:
Resource: $resource_type/$resource_name ($namespace)
Approver: $approver
Incident: $incident_id
Scenario: $scenario
Expires: $expiry
Justification: $justification"
    
    send_notification "$notification_message" "high"
    
    # Create audit event
    kubectl create event "emergency-deployment-approved" \
        --namespace="$namespace" \
        --reason="EmergencyDeploymentApproved" \
        --message="Emergency deployment approved by $approver for incident $incident_id" \
        --type="Warning" 2>/dev/null || warning "Failed to create audit event"
    
    return 0
}

# Function to revoke emergency deployment
revoke_emergency_deployment() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace="$3"
    local reason="$4"
    
    log "Revoking emergency deployment approval..."
    
    if [[ -z "$resource_type" || -z "$resource_name" || -z "$namespace" ]]; then
        error "Missing required parameters"
        echo "Usage: revoke_emergency_deployment <resource_type> <resource_name> <namespace> [reason]"
        return 1
    fi
    
    reason="${reason:-Manual revocation}"
    
    # Remove emergency annotations
    local annotations=(
        "security.policy/emergency-override-"
        "security.policy/approver-"
        "security.policy/justification-"
        "security.policy/incident-id-"
        "security.policy/scenario-"
        "security.policy/expiry-"
        "security.policy/approved-at-"
    )
    
    log "Removing emergency override annotations..."
    
    for annotation in "${annotations[@]}"; do
        kubectl annotate "$resource_type" "$resource_name" -n "$namespace" "$annotation" 2>/dev/null || true
    done
    
    # Add revocation annotation
    kubectl annotate "$resource_type" "$resource_name" -n "$namespace" \
        "security.policy/revoked-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "security.policy/revocation-reason=$reason" --overwrite
    
    success "Emergency deployment approval revoked"
    
    # Send notification
    local notification_message="Emergency deployment revoked:
Resource: $resource_type/$resource_name ($namespace)
Reason: $reason
Revoked at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    send_notification "$notification_message" "medium"
    
    # Create audit event
    kubectl create event "emergency-deployment-revoked" \
        --namespace="$namespace" \
        --reason="EmergencyDeploymentRevoked" \
        --message="Emergency deployment revoked: $reason" \
        --type="Warning" 2>/dev/null || warning "Failed to create audit event"
    
    return 0
}

# Function to list active emergency deployments
list_emergency_deployments() {
    log "Listing active emergency deployments..."
    
    echo
    echo "Active Emergency Deployments:"
    echo "============================="
    
    # Check pods
    kubectl get pods --all-namespaces \
        -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,APPROVER:.metadata.annotations.security\.policy/approver,INCIDENT:.metadata.annotations.security\.policy/incident-id,EXPIRY:.metadata.annotations.security\.policy/expiry" \
        --no-headers | grep -v '<none>' | while read line; do
        echo "Pod: $line"
    done
    
    # Check deployments
    kubectl get deployments --all-namespaces \
        -o custom-columns="NAMESPACE:.metadata.namespace,NAME:.metadata.name,APPROVER:.metadata.annotations.security\.policy/approver,INCIDENT:.metadata.annotations.security\.policy/incident-id,EXPIRY:.metadata.annotations.security\.policy/expiry" \
        --no-headers | grep -v '<none>' | while read line; do
        echo "Deployment: $line"
    done
    
    echo
}

# Main function
main() {
    local command="$1"
    shift
    
    case "$command" in
        "create")
            create_emergency_deployment "$@"
            ;;
        "revoke")
            revoke_emergency_deployment "$@"
            ;;
        "list")
            list_emergency_deployments
            ;;
        "validate")
            validate_approver "$1" "$2"
            ;;
        *)
            echo "Emergency Deployment Approval Tool"
            echo "Usage: $0 <command> [options]"
            echo
            echo "Commands:"
            echo "  create <resource_type> <resource_name> <namespace> <approver> <justification> <incident_id> [scenario] [duration]"
            echo "    Create emergency deployment approval"
            echo
            echo "  revoke <resource_type> <resource_name> <namespace> [reason]"
            echo "    Revoke emergency deployment approval"
            echo
            echo "  list"
            echo "    List active emergency deployments"
            echo
            echo "  validate <approver> <scenario>"
            echo "    Validate approver for scenario"
            echo
            echo "Examples:"
            echo "  $0 create deployment myapp production security-lead@company.com 'Critical security patch' INC-12345 security-incident 8h"
            echo "  $0 revoke deployment myapp production 'Incident resolved'"
            echo "  $0 list"
            echo "  $0 validate security-lead@company.com security-incident"
            exit 1
            ;;
    esac
}

# Check dependencies
if ! command -v kubectl &> /dev/null; then
    error "kubectl is required but not installed"
    exit 1
fi

if ! command -v yq &> /dev/null; then
    warning "yq is not installed, some features may not work properly"
fi

# Execute main function
main "$@"