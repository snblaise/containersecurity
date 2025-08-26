# Scratch Base Image for Static Binaries
# Ultra-minimal base image template for static binaries
# Provides maximum security with minimal attack surface

FROM scratch

# Copy CA certificates for HTTPS connections
# These should be copied from a builder stage that has ca-certificates
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy passwd file to define non-root user
# This file should be created in a builder stage
COPY passwd /etc/passwd

# Copy group file to define application group
# This file should be created in a builder stage  
COPY group /etc/group

# Create necessary directories (done in builder stage and copied)
COPY --chown=65534:65534 tmp /tmp
COPY --chown=65534:65534 app /app

# Switch to non-root user (nobody user - UID 65534)
USER 65534:65534

# Set working directory
WORKDIR /app

# Security labels
LABEL security.non-root="true" \
      security.user="nobody" \
      security.uid="65534" \
      security.gid="65534" \
      security.minimal="true" \
      base-image="scratch" \
      maintainer="security-team@company.com"

# Note: This Dockerfile requires a multi-stage build where:
# 1. A builder stage creates the passwd, group files and directory structure
# 2. The static binary is built in the builder stage
# 3. All artifacts are copied to this minimal scratch image
#
# Example builder stage commands:
# RUN echo 'nobody:x:65534:65534:nobody:/:/sbin/nologin' > /tmp/passwd
# RUN echo 'nobody:x:65534:' > /tmp/group  
# RUN mkdir -p /tmp/app /tmp/tmp && chown -R 65534:65534 /tmp/app /tmp/tmp