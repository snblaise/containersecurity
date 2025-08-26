#!/bin/bash

# SBOM Generation Script using Syft
# This script generates Software Bill of Materials (SBOM) for container images

set -e

# Configuration
IMAGE_NAME=${1:-""}
OUTPUT_FORMAT=${SBOM_FORMAT:-"spdx-json"}
OUTPUT_DIR=${SBOM_OUTPUT_DIR:-"./sbom-reports"}
AWS_REGION=${AWS_REGION:-"us-east-1"}
S3_BUCKET=${SBOM_S3_BUCKET:-""}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <image-name>"
    echo ""
    echo "Environment Variables:"
    echo "  SBOM_FORMAT          Output format (default: spdx-json)"
    echo "                       Options: spdx-json, spdx-tag-value, cyclonedx-json, cyclonedx-xml, syft-json"
    echo "  SBOM_OUTPUT_DIR      Output directory (default: ./sbom-reports)"
    echo "  SBOM_S3_BUCKET       S3 bucket for SBOM storage (optional)"
    echo "  AWS_REGION           AWS region (default: us-east-1)"
    echo ""
    echo "Examples:"
    echo "  $0 my-app:latest"
    echo "  $0 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.2.3"
    echo "  SBOM_FORMAT=cyclonedx-json $0 my-app:latest"
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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Validate inputs
if [ -z "$IMAGE_NAME" ]; then
    error "Image name is required"
    usage
fi

# Check if syft is installed
if ! command -v syft &> /dev/null; then
    error "syft is not installed. Please install it first:"
    echo "  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate timestamp for filenames
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
IMAGE_SAFE_NAME=$(echo "$IMAGE_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')
OUTPUT_FILE="$OUTPUT_DIR/sbom-${IMAGE_SAFE_NAME}-${TIMESTAMP}.${OUTPUT_FORMAT##*-}"

log "Starting SBOM generation for image: $IMAGE_NAME"
log "Output format: $OUTPUT_FORMAT"
log "Output file: $OUTPUT_FILE"

# Generate SBOM
log "Generating SBOM using syft..."
if syft "$IMAGE_NAME" -o "$OUTPUT_FORMAT=$OUTPUT_FILE"; then
    log "SBOM generated successfully: $OUTPUT_FILE"
else
    error "Failed to generate SBOM"
    exit 1
fi

# Validate SBOM file
if [ ! -f "$OUTPUT_FILE" ]; then
    error "SBOM file was not created: $OUTPUT_FILE"
    exit 1
fi

FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null || echo "0")
if [ "$FILE_SIZE" -eq 0 ]; then
    error "SBOM file is empty: $OUTPUT_FILE"
    exit 1
fi

log "SBOM file size: $(numfmt --to=iec $FILE_SIZE)"

# Generate SBOM summary
log "Generating SBOM summary..."
SUMMARY_FILE="$OUTPUT_DIR/sbom-summary-${IMAGE_SAFE_NAME}-${TIMESTAMP}.txt"

{
    echo "SBOM Generation Summary"
    echo "======================"
    echo "Image: $IMAGE_NAME"
    echo "Generated: $(date)"
    echo "Format: $OUTPUT_FORMAT"
    echo "File: $OUTPUT_FILE"
    echo "Size: $(numfmt --to=iec $FILE_SIZE)"
    echo ""
    
    # Extract package count based on format
    if [[ "$OUTPUT_FORMAT" == *"json"* ]]; then
        if command -v jq &> /dev/null; then
            PACKAGE_COUNT=$(jq '.packages | length' "$OUTPUT_FILE" 2>/dev/null || echo "N/A")
            echo "Total Packages: $PACKAGE_COUNT"
            
            # Top package types
            echo ""
            echo "Package Types:"
            jq -r '.packages | group_by(.type) | .[] | "\(.[0].type): \(length)"' "$OUTPUT_FILE" 2>/dev/null | head -10 || echo "Unable to extract package types"
        fi
    fi
    
    echo ""
    echo "SBOM Validation:"
    echo "✅ File created successfully"
    echo "✅ File size: $(numfmt --to=iec $FILE_SIZE)"
    
} > "$SUMMARY_FILE"

log "SBOM summary saved: $SUMMARY_FILE"

# Upload to S3 if bucket is specified
if [ -n "$S3_BUCKET" ]; then
    log "Uploading SBOM to S3 bucket: $S3_BUCKET"
    
    S3_KEY="sbom-reports/$(basename "$OUTPUT_FILE")"
    S3_SUMMARY_KEY="sbom-reports/$(basename "$SUMMARY_FILE")"
    
    if aws s3 cp "$OUTPUT_FILE" "s3://$S3_BUCKET/$S3_KEY" --region "$AWS_REGION"; then
        log "SBOM uploaded to S3: s3://$S3_BUCKET/$S3_KEY"
    else
        warn "Failed to upload SBOM to S3"
    fi
    
    if aws s3 cp "$SUMMARY_FILE" "s3://$S3_BUCKET/$S3_SUMMARY_KEY" --region "$AWS_REGION"; then
        log "SBOM summary uploaded to S3: s3://$S3_BUCKET/$S3_SUMMARY_KEY"
    else
        warn "Failed to upload SBOM summary to S3"
    fi
fi

# Generate metadata for CI/CD integration
METADATA_FILE="$OUTPUT_DIR/sbom-metadata-${IMAGE_SAFE_NAME}-${TIMESTAMP}.json"
{
    echo "{"
    echo "  \"image\": \"$IMAGE_NAME\","
    echo "  \"sbom_file\": \"$OUTPUT_FILE\","
    echo "  \"summary_file\": \"$SUMMARY_FILE\","
    echo "  \"format\": \"$OUTPUT_FORMAT\","
    echo "  \"generated_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"file_size\": $FILE_SIZE,"
    echo "  \"generator\": \"syft\","
    echo "  \"generator_version\": \"$(syft version 2>/dev/null | head -1 || echo 'unknown')\""
    if [ -n "$S3_BUCKET" ]; then
        echo "  ,\"s3_location\": \"s3://$S3_BUCKET/$S3_KEY\""
    fi
    echo "}"
} > "$METADATA_FILE"

log "SBOM metadata saved: $METADATA_FILE"

# Display final summary
echo ""
log "=== SBOM GENERATION COMPLETE ==="
echo "Image: $IMAGE_NAME"
echo "SBOM File: $OUTPUT_FILE"
echo "Summary: $SUMMARY_FILE"
echo "Metadata: $METADATA_FILE"
if [ -n "$S3_BUCKET" ]; then
    echo "S3 Location: s3://$S3_BUCKET/$S3_KEY"
fi
echo ""
log "SBOM generation completed successfully!"

# Set output for CI/CD systems
echo "SBOM_FILE=$OUTPUT_FILE" >> "${GITHUB_ENV:-/dev/null}" 2>/dev/null || true
echo "SBOM_SUMMARY=$SUMMARY_FILE" >> "${GITHUB_ENV:-/dev/null}" 2>/dev/null || true
echo "SBOM_METADATA=$METADATA_FILE" >> "${GITHUB_ENV:-/dev/null}" 2>/dev/null || true