#!/bin/bash

# Script to validate that secrets are not embedded in container images
# This script scans container images for potential secrets and sensitive data

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ECR_REGISTRY="${ECR_REGISTRY:-123456789012.dkr.ecr.us-east-1.amazonaws.com}"
TEMP_DIR=$(mktemp -d)
REPORT_FILE="${SCRIPT_DIR}/secrets-scan-report-$(date +%Y%m%d-%H%M%S).json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Function to check if required tools are installed
check_dependencies() {
    local missing_tools=()
    
    # Check for required tools
    for tool in docker jq trivy; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                docker)
                    echo "  - Docker: https://docs.docker.com/get-docker/"
                    ;;
                jq)
                    echo "  - jq: https://stedolan.github.io/jq/download/"
                    ;;
                trivy)
                    echo "  - Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
                    ;;
            esac
        done
        exit 1
    fi
}

# Function to scan image for secrets using trivy
scan_image_with_trivy() {
    local image="$1"
    local scan_results
    
    log_info "Scanning image with Trivy: $image"
    
    # Run trivy secret scan
    if scan_results=$(trivy image --format json --scanners secret "$image" 2>/dev/null); then
        echo "$scan_results"
    else
        log_error "Failed to scan image with Trivy: $image"
        echo "{\"Results\": []}"
    fi
}

# Function to scan image filesystem for potential secrets
scan_image_filesystem() {
    local image="$1"
    local container_id
    local findings=()
    
    log_info "Scanning image filesystem: $image"
    
    # Create and start container
    if container_id=$(docker create "$image" 2>/dev/null); then
        # Export container filesystem
        local export_file="$TEMP_DIR/$(basename "$image" | tr '/' '_' | tr ':' '_').tar"
        
        if docker export "$container_id" > "$export_file" 2>/dev/null; then
            # Extract and scan for potential secrets
            local extract_dir="$TEMP_DIR/$(basename "$export_file" .tar)"
            mkdir -p "$extract_dir"
            
            if tar -xf "$export_file" -C "$extract_dir" 2>/dev/null; then
                # Scan for common secret patterns
                local secret_patterns=(
                    "password.*=.*['\"][^'\"]{8,}['\"]"
                    "secret.*=.*['\"][^'\"]{16,}['\"]"
                    "key.*=.*['\"][^'\"]{16,}['\"]"
                    "token.*=.*['\"][^'\"]{20,}['\"]"
                    "api[_-]?key.*=.*['\"][^'\"]{16,}['\"]"
                    "private[_-]?key.*=.*['\"][^'\"]{32,}['\"]"
                    "-----BEGIN.*PRIVATE KEY-----"
                    "-----BEGIN.*CERTIFICATE-----"
                    "AKIA[0-9A-Z]{16}"  # AWS Access Key ID pattern
                    "[0-9a-zA-Z/+]{40}"  # AWS Secret Access Key pattern
                )
                
                for pattern in "${secret_patterns[@]}"; do
                    local matches
                    if matches=$(grep -r -i -E "$pattern" "$extract_dir" 2>/dev/null | head -10); then
                        if [ -n "$matches" ]; then
                            while IFS= read -r match; do
                                local file_path=$(echo "$match" | cut -d: -f1)
                                local relative_path=${file_path#$extract_dir}
                                findings+=("{\"file\": \"$relative_path\", \"pattern\": \"$pattern\", \"match\": \"$(echo "$match" | cut -d: -f2- | head -c 100)...\"}")
                            done <<< "$matches"
                        fi
                    fi
                done
            fi
            
            # Clean up
            rm -rf "$extract_dir" "$export_file"
        fi
        
        # Remove container
        docker rm "$container_id" >/dev/null 2>&1
    fi
    
    # Return findings as JSON array
    if [ ${#findings[@]} -gt 0 ]; then
        printf '[%s]' "$(IFS=,; echo "${findings[*]}")"
    else
        echo '[]'
    fi
}

# Function to scan environment variables in image
scan_image_env_vars() {
    local image="$1"
    local env_vars
    local findings=()
    
    log_info "Scanning environment variables: $image"
    
    # Get environment variables from image
    if env_vars=$(docker inspect "$image" --format='{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null); then
        # Check for suspicious environment variable patterns
        local suspicious_patterns=(
            "PASSWORD="
            "SECRET="
            "KEY="
            "TOKEN="
            "API_KEY="
            "PRIVATE_KEY="
            "DB_PASSWORD="
            "DATABASE_PASSWORD="
            "MYSQL_PASSWORD="
            "POSTGRES_PASSWORD="
        )
        
        while IFS= read -r env_var; do
            if [ -n "$env_var" ]; then
                for pattern in "${suspicious_patterns[@]}"; do
                    if echo "$env_var" | grep -i -q "$pattern"; then
                        # Check if the value looks like a real secret (not empty or placeholder)
                        local value=$(echo "$env_var" | cut -d= -f2-)
                        if [ -n "$value" ] && [ "$value" != "changeme" ] && [ "$value" != "placeholder" ] && [ ${#value} -gt 4 ]; then
                            findings+=("{\"env_var\": \"$(echo "$env_var" | cut -d= -f1)\", \"pattern\": \"$pattern\", \"has_value\": true}")
                        fi
                    fi
                done
            fi
        done <<< "$env_vars"
    fi
    
    # Return findings as JSON array
    if [ ${#findings[@]} -gt 0 ]; then
        printf '[%s]' "$(IFS=,; echo "${findings[*]}")"
    else
        echo '[]'
    fi
}

# Function to generate comprehensive report
generate_report() {
    local image="$1"
    local trivy_results="$2"
    local filesystem_findings="$3"
    local env_var_findings="$4"
    
    # Count findings
    local trivy_count=$(echo "$trivy_results" | jq '.Results | length' 2>/dev/null || echo "0")
    local filesystem_count=$(echo "$filesystem_findings" | jq '. | length' 2>/dev/null || echo "0")
    local env_var_count=$(echo "$env_var_findings" | jq '. | length' 2>/dev/null || echo "0")
    
    local total_findings=$((trivy_count + filesystem_count + env_var_count))
    
    # Generate report
    cat << EOF
{
  "image": "$image",
  "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": {
    "total_findings": $total_findings,
    "trivy_secrets": $trivy_count,
    "filesystem_findings": $filesystem_count,
    "environment_variables": $env_var_count,
    "status": "$([ $total_findings -eq 0 ] && echo "PASS" || echo "FAIL")"
  },
  "trivy_results": $trivy_results,
  "filesystem_findings": $filesystem_findings,
  "environment_variable_findings": $env_var_findings
}
EOF
}

# Function to scan a single image
scan_image() {
    local image="$1"
    
    log_info "Starting comprehensive scan for image: $image"
    
    # Pull image if not present locally
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        log_info "Pulling image: $image"
        if ! docker pull "$image" >/dev/null 2>&1; then
            log_error "Failed to pull image: $image"
            return 1
        fi
    fi
    
    # Run all scans
    local trivy_results=$(scan_image_with_trivy "$image")
    local filesystem_findings=$(scan_image_filesystem "$image")
    local env_var_findings=$(scan_image_env_vars "$image")
    
    # Generate and return report
    generate_report "$image" "$trivy_results" "$filesystem_findings" "$env_var_findings"
}

# Function to scan images from Kubernetes manifests
scan_kubernetes_images() {
    local manifest_dir="$1"
    local images=()
    
    log_info "Extracting images from Kubernetes manifests in: $manifest_dir"
    
    # Find all YAML files and extract image references
    while IFS= read -r -d '' file; do
        if [ -f "$file" ]; then
            # Extract image references from YAML
            local file_images
            file_images=$(grep -E "^\s*image:\s*" "$file" | sed 's/.*image:\s*//' | sed 's/["\x27]//g' | sort -u)
            
            while IFS= read -r image; do
                if [ -n "$image" ] && [[ "$image" != *"latest"* ]]; then
                    images+=("$image")
                fi
            done <<< "$file_images"
        fi
    done < <(find "$manifest_dir" -name "*.yaml" -o -name "*.yml" -print0)
    
    # Remove duplicates
    local unique_images=($(printf '%s\n' "${images[@]}" | sort -u))
    
    echo "${unique_images[@]}"
}

# Main execution function
main() {
    local scan_mode="${1:-manifests}"
    local target="${2:-../pod-examples}"
    
    log_info "Starting secrets validation scan"
    log_info "Mode: $scan_mode"
    log_info "Target: $target"
    
    # Check dependencies
    check_dependencies
    
    # Initialize report
    local all_reports=()
    local failed_scans=0
    
    case "$scan_mode" in
        "image")
            # Scan single image
            local report
            if report=$(scan_image "$target"); then
                all_reports+=("$report")
                
                # Check if scan passed
                local status=$(echo "$report" | jq -r '.summary.status')
                if [ "$status" = "FAIL" ]; then
                    ((failed_scans++))
                fi
            else
                ((failed_scans++))
            fi
            ;;
        "manifests")
            # Scan images from Kubernetes manifests
            local images
            images=($(scan_kubernetes_images "$target"))
            
            if [ ${#images[@]} -eq 0 ]; then
                log_warn "No images found in manifests directory: $target"
                exit 0
            fi
            
            log_info "Found ${#images[@]} unique images to scan"
            
            for image in "${images[@]}"; do
                local report
                if report=$(scan_image "$image"); then
                    all_reports+=("$report")
                    
                    # Check if scan passed
                    local status=$(echo "$report" | jq -r '.summary.status')
                    if [ "$status" = "FAIL" ]; then
                        ((failed_scans++))
                    fi
                else
                    ((failed_scans++))
                fi
            done
            ;;
        *)
            log_error "Invalid scan mode: $scan_mode"
            log_info "Usage: $0 [image|manifests] [target]"
            exit 1
            ;;
    esac
    
    # Generate final report
    local final_report
    final_report=$(cat << EOF
{
  "scan_summary": {
    "total_images": ${#all_reports[@]},
    "failed_scans": $failed_scans,
    "passed_scans": $((${#all_reports[@]} - failed_scans)),
    "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "overall_status": "$([ $failed_scans -eq 0 ] && echo "PASS" || echo "FAIL")"
  },
  "image_reports": [$(IFS=,; echo "${all_reports[*]}")]
}
EOF
)
    
    # Save report
    echo "$final_report" | jq '.' > "$REPORT_FILE"
    log_info "Detailed report saved to: $REPORT_FILE"
    
    # Print summary
    echo ""
    log_info "=== SECRETS VALIDATION SUMMARY ==="
    echo "Total images scanned: ${#all_reports[@]}"
    echo "Passed: $((${#all_reports[@]} - failed_scans))"
    echo "Failed: $failed_scans"
    echo ""
    
    if [ $failed_scans -eq 0 ]; then
        log_info "✅ All images passed secrets validation!"
        echo "No secrets detected in container images."
    else
        log_error "❌ $failed_scans image(s) failed secrets validation!"
        echo "Secrets or sensitive data detected in container images."
        echo "Review the detailed report: $REPORT_FILE"
    fi
    
    # Clean up
    rm -rf "$TEMP_DIR"
    
    # Exit with appropriate code
    exit $failed_scans
}

# Cleanup function
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Set trap for cleanup
trap cleanup EXIT

# Run main function with all arguments
main "$@"