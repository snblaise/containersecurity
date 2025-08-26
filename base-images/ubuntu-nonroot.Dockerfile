# Ubuntu Base Image with Non-Root User Configuration
# Secure base image template for Ubuntu-based applications
# Follows financial services security requirements

FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update system packages and install security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create application group and user with specific UID/GID
# Using UID/GID 1001 to avoid conflicts with system users
RUN groupadd -g 1001 appgroup && \
    useradd -r -u 1001 -g appgroup -d /home/appuser -s /usr/sbin/nologin -c "Application User" appuser

# Create application directories with proper ownership
RUN mkdir -p /app /app/data /app/logs /app/tmp && \
    chown -R appuser:appgroup /app && \
    chmod -R 755 /app

# Create home directory for the user
RUN mkdir -p /home/appuser && \
    chown appuser:appgroup /home/appuser && \
    chmod 755 /home/appuser

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
CMD ["bash", "-c", "echo 'This is a base image. Please specify a command.'"]

# Security labels
LABEL security.non-root="true" \
      security.user="appuser" \
      security.uid="1001" \
      security.gid="1001" \
      base-image="ubuntu:22.04" \
      maintainer="security-team@company.com"