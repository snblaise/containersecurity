# Alpine Linux Base Image with Non-Root User Configuration
# Secure base image template for Alpine-based applications
# Follows financial services security requirements

FROM alpine:3.18

# Install security updates and remove package cache
RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates tzdata && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Create application group and user with specific UID/GID
# Using UID/GID 1001 to avoid conflicts with system users
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup -h /home/appuser -s /sbin/nologin appuser

# Create application directories with proper ownership
RUN mkdir -p /app /app/data /app/logs /app/tmp && \
    chown -R appuser:appgroup /app && \
    chmod -R 755 /app

# Create tmp directory for application use
RUN mkdir -p /tmp/app && \
    chown appuser:appgroup /tmp/app && \
    chmod 755 /tmp/app

# Switch to non-root user
USER 1001:1001

# Set working directory
WORKDIR /app

# Set secure environment variables
ENV HOME=/home/appuser \
    USER=appuser \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Default command (should be overridden by child images)
CMD ["sh", "-c", "echo 'This is a base image. Please specify a command.'"]

# Security labels
LABEL security.non-root="true" \
      security.user="appuser" \
      security.uid="1001" \
      security.gid="1001" \
      base-image="alpine:3.18" \
      maintainer="security-team@company.com"