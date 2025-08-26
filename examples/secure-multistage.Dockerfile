# Multi-Stage Dockerfile with Security Hardening
# This example demonstrates secure Docker practices for a Go application
# following financial services security requirements

# Build stage - includes build tools and dependencies
FROM golang:1.21-alpine3.18 AS builder

# Install security updates and minimal required packages
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates git && \
    rm -rf /var/cache/apk/*

# Create non-root user for build process
RUN addgroup -g 1001 buildgroup && \
    adduser -D -u 1001 -G buildgroup builduser

# Set working directory and change ownership
WORKDIR /build
RUN chown builduser:buildgroup /build

# Switch to non-root user for build
USER builduser:buildgroup

# Copy dependency files first for better layer caching
COPY --chown=builduser:buildgroup go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY --chown=builduser:buildgroup . .

# Build the application with security flags
RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
    -a \
    -installsuffix cgo \
    -ldflags='-w -s -extldflags "-static"' \
    -o app \
    ./cmd/main.go

# Verify the binary
RUN file app && ldd app || true

# Production stage - minimal runtime environment
FROM gcr.io/distroless/static-debian11:nonroot

# Copy CA certificates for HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary from builder stage
COPY --from=builder --chown=65534:65534 /build/app /usr/local/bin/app

# Use distroless nonroot user (UID 65534)
USER 65534:65534

# Expose application port (non-privileged port)
EXPOSE 8080

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/app", "healthcheck"]

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/app"]

# Security labels for metadata
LABEL security.scan="required" \
      security.non-root="true" \
      security.read-only="true" \
      security.capabilities="none" \
      maintainer="security-team@company.com" \
      version="1.0.0"