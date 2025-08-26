#!/bin/bash

# Docker Security Validation Script
# Validates Docker images and containers against security best practices
# Usage: ./validate-docker-security.sh <image_name>

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="${1:-}"
TEMP_DIR=$(mktemp -d)
RESULTS_FILE="${TEMP_DIR}/security_results.txt"

# Cleanup function
cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

# Print functions
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Usage function
usage() {
    echo "Usage: $0 <image_name>"
    echo "Example: $0 myapp:latest"
    exit 1
}

# Validate input
if [[ -z "${IMAGE_NAME}" ]]; then
    usage
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not in PATH"
    exit 1
fi

# Check if image exists
if ! docker image inspect "${IMAGE_NAME}" &> /dev/null; then
    print_error "Image '${IMAGE_NAME}' not found"
    exit 1
fi

print_header "Docker Security Validation for ${IMAGE_NAME}"

# Initialize counters
PASSED=0
FAILED=0
WARNINGS=0

# Test 1: Check if image runs as non-root user
print_info "Checking user configuration..."
USER_INFO=$(docker image inspect "${IMAGE_NAME}" --format '{{.Config.User}}')
if [[ -n "${USER_INFO}" && "${USER_INFO}" != "0" && "${USER_INFO}" != "root" ]]; then
    print_success "Image configured to run as non-root user: ${USER_INFO}"
    ((PASSED++))
else
    print_error "Image not configured to run as non-root user"
    ((FAILED++))
fi

# Test 2: Check for exposed privileged ports
print_info "Checking exposed ports..."
EXPOSED_PORTS=$(docker image inspect "${IMAGE_NAME}" --format '{{range $port, $config := .Config.ExposedPorts}}{{$port}} {{end}}')
PRIVILEGED_PORTS=false
for port in ${EXPOSED_PORTS}; do
    port_num=$(echo "${port}" | cut -d'/' -f1)
    if [[ "${port_num}" -lt 1024 ]]; then
        print_error "Privileged port exposed: ${port}"
        PRIVILEGED_PORTS=true
        ((FAILED++))
    fi
done

if [[ "${PRIVILEGED_PORTS}" == false ]] && [[ -n "${EXPOSED_PORTS}" ]]; then
    print_success "All exposed ports are non-privileged: ${EXPOSED_PORTS}"
    ((PASSED++))
elif [[ -z "${EXPOSED_PORTS}" ]]; then
    print_warning "No ports exposed in image"
    ((WARNINGS++))
fi

# Test 3: Check image size (should be reasonable)
print_info "Checking image size..."
IMAGE_SIZE=$(docker image inspect "${IMAGE_NAME}" --format '{{.Size}}')
IMAGE_SIZE_MB=$((IMAGE_SIZE / 1024 / 1024))

if [[ "${IMAGE_SIZE_MB}" -lt 100 ]]; then
    print_success "Image size is optimal: ${IMAGE_SIZE_MB}MB"
    ((PASSED++))
elif [[ "${IMAGE_SIZE_MB}" -lt 500 ]]; then
    print_warning "Image size is acceptable: ${IMAGE_SIZE_MB}MB"
    ((WARNINGS++))
else
    print_error "Image size is too large: ${IMAGE_SIZE_MB}MB (consider optimization)"
    ((FAILED++))
fi

# Test 4: Check for security labels
print_info "Checking security labels..."
SECURITY_LABELS=$(docker image inspect "${IMAGE_NAME}" --format '{{range $key, $value := .Config.Labels}}{{if contains $key "security"}}{{$key}}={{$value}} {{end}}{{end}}')

if [[ -n "${SECURITY_LABELS}" ]]; then
    print_success "Security labels found: ${SECURITY_LABELS}"
    ((PASSED++))
else
    print_warning "No security labels found (recommended for compliance)"
    ((WARNINGS++))
fi

# Test 5: Check for health check
print_info "Checking health check configuration..."
HEALTHCHECK=$(docker image inspect "${IMAGE_NAME}" --format '{{.Config.Healthcheck}}')

if [[ "${HEALTHCHECK}" != "<nil>" ]] && [[ -n "${HEALTHCHECK}" ]]; then
    print_success "Health check configured"
    ((PASSED++))
else
    print_warning "No health check configured (recommended for production)"
    ((WARNINGS++))
fi

# Test 6: Run container security test
print_info "Running container security test..."
CONTAINER_ID=$(docker run -d --rm "${IMAGE_NAME}" sleep 30 2>/dev/null || echo "")

if [[ -n "${CONTAINER_ID}" ]]; then
    # Check if container is running as non-root
    CONTAINER_USER=$(docker exec "${CONTAINER_ID}" id -u 2>/dev/null || echo "unknown")
    if [[ "${CONTAINER_USER}" != "0" ]] && [[ "${CONTAINER_USER}" != "unknown" ]]; then
        print_success "Container running as non-root user (UID: ${CONTAINER_USER})"
        ((PASSED++))
    else
        print_error "Container running as root user or user check failed"
        ((FAILED++))
    fi
    
    # Check filesystem permissions
    ROOT_WRITABLE=$(docker exec "${CONTAINER_ID}" test -w / && echo "true" || echo "false")
    if [[ "${ROOT_WRITABLE}" == "false" ]]; then
        print_success "Root filesystem is read-only"
        ((PASSED++))
    else
        print_warning "Root filesystem is writable (consider read-only filesystem)"
        ((WARNINGS++))
    fi
    
    # Cleanup container
    docker stop "${CONTAINER_ID}" &>/dev/null || true
else
    print_warning "Could not start container for runtime testing"
    ((WARNINGS++))
fi

# Test 7: Check for common vulnerabilities using docker scout (if available)
print_info "Checking for vulnerabilities..."
if command -v docker &> /dev/null && docker scout version &> /dev/null; then
    VULN_OUTPUT=$(docker scout cves "${IMAGE_NAME}" --format sarif 2>/dev/null || echo "")
    if [[ -n "${VULN_OUTPUT}" ]]; then
        CRITICAL_VULNS=$(echo "${VULN_OUTPUT}" | grep -c '"level": "error"' || echo "0")
        HIGH_VULNS=$(echo "${VULN_OUTPUT}" | grep -c '"level": "warning"' || echo "0")
        
        if [[ "${CRITICAL_VULNS}" -eq 0 ]] && [[ "${HIGH_VULNS}" -eq 0 ]]; then
            print_success "No critical or high vulnerabilities found"
            ((PASSED++))
        elif [[ "${CRITICAL_VULNS}" -eq 0 ]]; then
            print_warning "${HIGH_VULNS} high severity vulnerabilities found"
            ((WARNINGS++))
        else
            print_error "${CRITICAL_VULNS} critical vulnerabilities found"
            ((FAILED++))
        fi
    else
        print_warning "Could not scan for vulnerabilities"
        ((WARNINGS++))
    fi
else
    print_warning "Docker Scout not available for vulnerability scanning"
    ((WARNINGS++))
fi

# Summary
print_header "Security Validation Summary"
echo -e "Image: ${BLUE}${IMAGE_NAME}${NC}"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo -e "Warnings: ${YELLOW}${WARNINGS}${NC}"

# Calculate score
TOTAL_TESTS=$((PASSED + FAILED + WARNINGS))
if [[ "${TOTAL_TESTS}" -gt 0 ]]; then
    SCORE=$(( (PASSED * 100) / TOTAL_TESTS ))
    echo -e "Security Score: ${BLUE}${SCORE}%${NC}"
    
    if [[ "${SCORE}" -ge 80 ]] && [[ "${FAILED}" -eq 0 ]]; then
        print_success "Image passes security validation"
        exit 0
    elif [[ "${FAILED}" -eq 0 ]]; then
        print_warning "Image has warnings but no critical failures"
        exit 0
    else
        print_error "Image failed security validation"
        exit 1
    fi
else
    print_error "No tests could be executed"
    exit 1
fi