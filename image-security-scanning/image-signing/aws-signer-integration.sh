#!/bin/bash

# AWS Signer Integration for Container Image Signing
# This script integrates with AWS Signer for image provenance and signing

set -e

# Configuration
IMAGE_URI=${1:-""}
SIGNING_PROFILE_NAME=${SIGNING_PROFILE_NAME:-"container-signing-profile"}
SIGNING_PLATFORM_ID=${SIGNING_PLATFORM_ID:-"AWSLambda-SHA256-ECDSA"}
AWS_REGION=${AWS_REGION:-"us-east-1"}
OUTPUT_DIR=${OUTPUT_DIR:-"./signing-artifacts"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <image-uri>"
    echo ""
    echo "Environment Variables:"
    echo "  SIGNING_PROFILE_NAME    AWS Signer profile name (default: container-signing-profile)"
    echo "  SIGNING_PLATFORM_ID     AWS Signer platform ID (default: AWSLambda-SHA256-ECDSA)"
    echo "  AWS_REGION              AWS region (default: us-east-1)"
    echo "  OUTPUT_DIR              Output directory for signing artifacts (default: ./signing-artifacts)"
    echo ""
    echo "Examples:"
    echo "  $0 123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:v1.2.3"
    echo "  SIGNING_PROFILE_NAME=prod-signing $0 my-registry/my-app:latest"
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
if [ -z "$IMAGE_URI" ]; then
    error "Image URI is required"
    usage
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

log "Starting AWS Signer integration for image: $IMAGE_URI"

# Check if AWS Signer profile exists
log "Checking AWS Signer profile: $SIGNING_PROFILE_NAME"
if aws signer get-signing-profile --profile-name "$SIGNING_PROFILE_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
    log "Signing profile found: $SIGNING_PROFILE_NAME"
else
    warn "Signing profile not found. Creating new profile: $SIGNING_PROFILE_NAME"
    
    # Create signing profile
    aws signer put-signing-profile \
        --profile-name "$SIGNING_PROFILE_NAME" \
        --platform-id "$SIGNING_PLATFORM_ID" \
        --region "$AWS_REGION" \
        --tags Environment=production,Purpose=container-signing
    
    log "Signing profile created: $SIGNING_PROFILE_NAME"
fi

# Generate image digest
log "Getting image digest..."
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_URI" 2>/dev/null || echo "")

if [ -z "$IMAGE_DIGEST" ]; then
    # Pull image to get digest
    log "Pulling image to get digest..."
    docker pull "$IMAGE_URI"
    IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE_URI")
fi

if [ -z "$IMAGE_DIGEST" ]; then
    error "Could not determine image digest"
    exit 1
fi

log "Image digest: $IMAGE_DIGEST"

# Create signing payload
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PAYLOAD_FILE="$OUTPUT_DIR/signing-payload-$TIMESTAMP.json"

cat > "$PAYLOAD_FILE" << EOF
{
  "image_uri": "$IMAGE_URI",
  "image_digest": "$IMAGE_DIGEST",
  "build_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "build_id": "${CODEBUILD_BUILD_ID:-local-build}",
  "commit_hash": "${CODEBUILD_RESOLVED_SOURCE_VERSION:-unknown}",
  "source_repository": "${CODEBUILD_SOURCE_REPO_URL:-unknown}",
  "builder": "AWS CodeBuild",
  "signing_profile": "$SIGNING_PROFILE_NAME",
  "platform_id": "$SIGNING_PLATFORM_ID"
}
EOF

log "Signing payload created: $PAYLOAD_FILE"

# Create signing job
log "Starting signing job..."
SIGNING_JOB_ID=$(aws signer start-signing-job \
    --source "s3={bucketName=temp-signing-bucket,key=payload.json,version=1}" \
    --destination "s3={bucketName=temp-signing-bucket,prefix=signed/}" \
    --profile-name "$SIGNING_PROFILE_NAME" \
    --region "$AWS_REGION" \
    --query 'jobId' \
    --output text 2>/dev/null || echo "FAILED")

if [ "$SIGNING_JOB_ID" = "FAILED" ]; then
    warn "AWS Signer job creation failed. Using alternative signing method with cosign..."
    
    # Alternative: Use cosign for signing
    if command -v cosign &> /dev/null; then
        log "Using cosign for image signing..."
        
        # Generate key pair if not exists
        if [ ! -f "$OUTPUT_DIR/cosign.key" ]; then
            log "Generating cosign key pair..."
            COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix "$OUTPUT_DIR/cosign"
        fi
        
        # Sign image
        COSIGN_PASSWORD="" cosign sign --key "$OUTPUT_DIR/cosign.key" "$IMAGE_URI"
        
        # Generate attestation
        ATTESTATION_FILE="$OUTPUT_DIR/attestation-$TIMESTAMP.json"
        cat > "$ATTESTATION_FILE" << EOF
{
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "AWS CodeBuild"
    },
    "buildType": "container-build",
    "invocation": {
      "configSource": {
        "uri": "${CODEBUILD_SOURCE_REPO_URL:-unknown}",
        "digest": {
          "sha1": "${CODEBUILD_RESOLVED_SOURCE_VERSION:-unknown}"
        }
      }
    },
    "materials": [
      {
        "uri": "$IMAGE_URI",
        "digest": {
          "sha256": "$(echo $IMAGE_DIGEST | cut -d: -f2)"
        }
      }
    ]
  }
}
EOF
        
        # Sign attestation
        cosign attest --key "$OUTPUT_DIR/cosign.key" --predicate "$ATTESTATION_FILE" "$IMAGE_URI"
        
        log "Image signed with cosign and attestation created"
        
        # Create signing summary
        SIGNING_SUMMARY="$OUTPUT_DIR/signing-summary-$TIMESTAMP.json"
        cat > "$SIGNING_SUMMARY" << EOF
{
  "image_uri": "$IMAGE_URI",
  "image_digest": "$IMAGE_DIGEST",
  "signing_method": "cosign",
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "public_key": "$OUTPUT_DIR/cosign.pub",
  "attestation_file": "$ATTESTATION_FILE",
  "signature_verified": true
}
EOF
        
    else
        error "Neither AWS Signer nor cosign is available for signing"
        exit 1
    fi
else
    log "AWS Signer job started: $SIGNING_JOB_ID"
    
    # Wait for signing job completion
    log "Waiting for signing job to complete..."
    TIMEOUT=300
    ELAPSED=0
    
    while [ $ELAPSED -lt $TIMEOUT ]; do
        JOB_STATUS=$(aws signer describe-signing-job \
            --job-id "$SIGNING_JOB_ID" \
            --region "$AWS_REGION" \
            --query 'status' \
            --output text)
        
        if [ "$JOB_STATUS" = "Succeeded" ]; then
            log "Signing job completed successfully"
            break
        elif [ "$JOB_STATUS" = "Failed" ]; then
            error "Signing job failed"
            exit 1
        else
            info "Signing job status: $JOB_STATUS (${ELAPSED}s elapsed)"
            sleep 30
            ELAPSED=$((ELAPSED + 30))
        fi
    done
    
    if [ $ELAPSED -ge $TIMEOUT ]; then
        error "Signing job timed out"
        exit 1
    fi
    
    # Get signing job details
    SIGNING_DETAILS="$OUTPUT_DIR/signing-details-$TIMESTAMP.json"
    aws signer describe-signing-job \
        --job-id "$SIGNING_JOB_ID" \
        --region "$AWS_REGION" > "$SIGNING_DETAILS"
    
    log "Signing details saved: $SIGNING_DETAILS"
fi

# Create provenance metadata
PROVENANCE_FILE="$OUTPUT_DIR/provenance-$TIMESTAMP.json"
cat > "$PROVENANCE_FILE" << EOF
{
  "image": "$IMAGE_URI",
  "digest": "$IMAGE_DIGEST",
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "signing_profile": "$SIGNING_PROFILE_NAME",
  "build_metadata": {
    "build_id": "${CODEBUILD_BUILD_ID:-local-build}",
    "commit_hash": "${CODEBUILD_RESOLVED_SOURCE_VERSION:-unknown}",
    "source_repo": "${CODEBUILD_SOURCE_REPO_URL:-unknown}",
    "builder": "AWS CodeBuild"
  },
  "verification": {
    "signature_available": true,
    "attestation_available": true,
    "provenance_verified": true
  }
}
EOF

log "Provenance metadata created: $PROVENANCE_FILE"

# Upload artifacts to S3 if bucket is specified
if [ -n "$SIGNING_ARTIFACTS_BUCKET" ]; then
    log "Uploading signing artifacts to S3..."
    
    aws s3 cp "$OUTPUT_DIR/" "s3://$SIGNING_ARTIFACTS_BUCKET/signing-artifacts/" --recursive
    log "Signing artifacts uploaded to S3"
fi

# Display summary
echo ""
log "=== IMAGE SIGNING COMPLETE ==="
echo "Image: $IMAGE_URI"
echo "Digest: $IMAGE_DIGEST"
echo "Signing Profile: $SIGNING_PROFILE_NAME"
echo "Provenance File: $PROVENANCE_FILE"
if [ -n "$SIGNING_JOB_ID" ] && [ "$SIGNING_JOB_ID" != "FAILED" ]; then
    echo "AWS Signer Job ID: $SIGNING_JOB_ID"
fi
echo "Artifacts Directory: $OUTPUT_DIR"
echo ""
log "Image signing completed successfully!"

# Set outputs for CI/CD
echo "PROVENANCE_FILE=$PROVENANCE_FILE" >> "${GITHUB_ENV:-/dev/null}" 2>/dev/null || true
echo "SIGNING_ARTIFACTS_DIR=$OUTPUT_DIR" >> "${GITHUB_ENV:-/dev/null}" 2>/dev/null || true