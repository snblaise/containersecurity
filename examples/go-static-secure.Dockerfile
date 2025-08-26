# Secure Go Static Binary Dockerfile
# Demonstrates building a static Go binary with scratch base

# Build Stage
FROM golang:1.21-alpine AS builder

# Install git for go modules and ca-certificates
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user for build
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY --chown=appuser:appgroup . .

# Switch to non-root user for build
USER appuser

# Build static binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o app ./cmd/main.go

# Production Stage - Scratch with minimal runtime
FROM scratch AS production

# Copy CA certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Create minimal user database
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy the static binary
COPY --from=builder --chown=1001:1001 /app/app /app

# Use non-root user
USER 1001:1001

# Expose non-privileged port
EXPOSE 8080

# Health check (requires HTTP client in binary)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app", "-health-check"]

# Start the application
ENTRYPOINT ["/app"]

# Security metadata
LABEL security.scan="required" \
      security.signature="required" \
      security.base="scratch" \
      security.nonroot="true" \
      security.static="true"