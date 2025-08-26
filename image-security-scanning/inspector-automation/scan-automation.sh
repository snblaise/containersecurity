#!/bin/bash

# ECR Inspector Scanning Automation Script
# This script automates the process of scanning container images and enforcing vulnerability thresholds

set -e

# Configuration
AWS_REGION=${AWS_REGION:-us-east-1}
REPOSITORY_NAME=${1:-""}
IMAGE_TAG=${2:-"latest"}
CRITICAL_THRESHOLD=${CRITICAL_THRESHOLD:-0}
HIGH_THRESHOLD=${HIGH_THRESHOLD:-5}
MEDIUM_THRESHOLD=${MEDIUM_THRESHOLD:-20}
SCAN_TIMEOUT=${SCAN_TIMEOUT:-600}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <repository-name> [image-tag]"
    echo ""
    echo "Environment Variables:"
    echo "  AWS_REGION           AWS region (default: us-east-1)"
    echo "  CRITICAL_THRESHOLD   Max critical vulnerabilities (default: 0)"
    echo "  HIGH_THRESHOLD       Max high vulnerabilities (default: 5)"
    echo "  MEDIUM_THRESHOLD     Max medium vulnerabilities (default: 20)"
    echo "  SCAN_TIMEOUT         Scan timeout in seconds (default: 600)"
    echo ""
    echo "Example:"
    echo "  $0 my-app-repo v1.2.3"
    echo "  CRITICAL_THRESHOLD=0 HIGH_THRESHOLD=3 $0 my-app-repo latest"
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

# Validate inputs
if [ -z "$REPOSITORY_NAME" ]; then
    error "Repository name is required"
    usage
fi

log "Starting ECR Inspector scan for $REPOSITORY_NAME:$IMAGE_TAG"
log "Vulnerability thresholds - Critical: $CRITICAL_THRESHOLD, High: $HIGH_THRESHOLD, Medium: $MEDIUM_THRESHOLD"

# Check if repository exists
if ! aws ecr describe-repositories --repository-names "$REPOSITORY_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
    error "Repository $REPOSITORY_NAME not found in region $AWS_REGION"
    exit 1
fi

# Check if image exists
if ! aws ecr describe-images --repository-name "$REPOSITORY_NAME" --image-ids imageTag="$IMAGE_TAG" --region "$AWS_REGION" >/dev/null 2>&1; then
    error "Image $REPOSITORY_NAME:$IMAGE_TAG not found"
    exit 1
fi

# Start image scan
log "Initiating image scan..."
SCAN_RESULT=$(aws ecr start-image-scan \
    --repository-name "$REPOSITORY_NAME" \
    --image-id imageTag="$IMAGE_TAG" \
    --region "$AWS_REGION" 2>&1 || true)

if echo "$SCAN_RESULT" | grep -q "ScanInProgressException"; then
    log "Scan already in progress, waiting for completion..."
elif echo "$SCAN_RESULT" | grep -q "UnsupportedImageTypeException"; then
    error "Image type not supported for scanning"
    exit 1
elif echo "$SCAN_RESULT" | grep -q "LimitExceededException"; then
    error "Scan limit exceeded, please try again later"
    exit 1
else
    log "Scan initiated successfully"
fi

# Wait for scan completion
log "Waiting for scan to complete (timeout: ${SCAN_TIMEOUT}s)..."
ELAPSED=0
SCAN_STATUS="IN_PROGRESS"

while [ "$SCAN_STATUS" = "IN_PROGRESS" ] && [ $ELAPSED -lt $SCAN_TIMEOUT ]; do
    sleep 30
    ELAPSED=$((ELAPSED + 30))
    
    SCAN_FINDINGS=$(aws ecr describe-image-scan-findings \
        --repository-name "$REPOSITORY_NAME" \
        --image-id imageTag="$IMAGE_TAG" \
        --region "$AWS_REGION" 2>/dev/null || echo '{"imageScanStatus":{"status":"IN_PROGRESS"}}')
    
    SCAN_STATUS=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanStatus.status')
    
    if [ "$SCAN_STATUS" = "IN_PROGRESS" ]; then
        log "Scan in progress... (${ELAPSED}s elapsed)"
    elif [ "$SCAN_STATUS" = "COMPLETE" ]; then
        log "Scan completed successfully"
        break
    elif [ "$SCAN_STATUS" = "FAILED" ]; then
        error "Scan failed"
        exit 1
    fi
done

if [ "$SCAN_STATUS" != "COMPLETE" ]; then
    error "Scan did not complete within timeout period (${SCAN_TIMEOUT}s)"
    exit 1
fi

# Parse scan results
CRITICAL_COUNT=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findingCounts.CRITICAL // 0')
HIGH_COUNT=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findingCounts.HIGH // 0')
MEDIUM_COUNT=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findingCounts.MEDIUM // 0')
LOW_COUNT=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findingCounts.LOW // 0')
INFORMATIONAL_COUNT=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findingCounts.INFORMATIONAL // 0')
UNDEFINED_COUNT=$(echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findingCounts.UNDEFINED // 0')

# Display results
echo ""
log "=== VULNERABILITY SCAN RESULTS ==="
echo "Repository: $REPOSITORY_NAME:$IMAGE_TAG"
echo "Scan Status: $SCAN_STATUS"
echo ""
echo "Vulnerability Counts:"
echo "  Critical:      $CRITICAL_COUNT"
echo "  High:          $HIGH_COUNT"
echo "  Medium:        $MEDIUM_COUNT"
echo "  Low:           $LOW_COUNT"
echo "  Informational: $INFORMATIONAL_COUNT"
echo "  Undefined:     $UNDEFINED_COUNT"
echo ""

# Check thresholds and determine if build should fail
THRESHOLD_EXCEEDED=false

if [ "$CRITICAL_COUNT" -gt "$CRITICAL_THRESHOLD" ]; then
    error "Critical vulnerabilities ($CRITICAL_COUNT) exceed threshold ($CRITICAL_THRESHOLD)"
    THRESHOLD_EXCEEDED=true
fi

if [ "$HIGH_COUNT" -gt "$HIGH_THRESHOLD" ]; then
    error "High vulnerabilities ($HIGH_COUNT) exceed threshold ($HIGH_THRESHOLD)"
    THRESHOLD_EXCEEDED=true
fi

if [ "$MEDIUM_COUNT" -gt "$MEDIUM_THRESHOLD" ]; then
    warn "Medium vulnerabilities ($MEDIUM_COUNT) exceed threshold ($MEDIUM_THRESHOLD)"
    # Note: Medium vulnerabilities typically don't fail the build, just warn
fi

# Generate detailed findings report
FINDINGS_FILE="vulnerability-report-$(date +%Y%m%d-%H%M%S).json"
echo "$SCAN_FINDINGS" > "$FINDINGS_FILE"
log "Detailed findings saved to: $FINDINGS_FILE"

# Extract and display critical/high findings
if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
    echo ""
    log "=== CRITICAL AND HIGH SEVERITY FINDINGS ==="
    echo "$SCAN_FINDINGS" | jq -r '.imageScanFindings.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH") | "Severity: \(.severity)\nName: \(.name)\nDescription: \(.description)\nURI: \(.uri)\n---"'
fi

# Final decision
if [ "$THRESHOLD_EXCEEDED" = true ]; then
    error "Image failed vulnerability threshold checks"
    echo ""
    echo "To proceed, either:"
    echo "1. Fix the vulnerabilities in your image"
    echo "2. Adjust the vulnerability thresholds (not recommended for production)"
    echo "3. Add exceptions for specific CVEs (requires security team approval)"
    exit 1
else
    log "Image passed all vulnerability threshold checks"
    echo ""
    log "=== SCAN SUMMARY ==="
    echo "✅ Critical: $CRITICAL_COUNT/$CRITICAL_THRESHOLD"
    echo "✅ High: $HIGH_COUNT/$HIGH_THRESHOLD"
    echo "ℹ️  Medium: $MEDIUM_COUNT/$MEDIUM_THRESHOLD"
    echo ""
    log "Image is approved for deployment"
    exit 0
fi