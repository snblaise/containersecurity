# Secure Python Application Dockerfile
# Demonstrates security hardening for Python applications

# Build Stage
FROM python:3.11-slim AS builder

# Install security updates and build dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -u 1001 appuser

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appgroup . .

# Production Stage - Distroless Python runtime
FROM gcr.io/distroless/python3-debian11:nonroot AS production

# Copy Python packages and application from builder
COPY --from=builder --chown=nonroot:nonroot /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder --chown=nonroot:nonroot /app /app

# Set Python path
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages

WORKDIR /app

# Use distroless nonroot user
USER nonroot

# Expose non-privileged port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/bin/python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

# Start application
ENTRYPOINT ["/usr/bin/python3", "app.py"]

# Security metadata
LABEL security.scan="required" \
      security.signature="required" \
      base.image="distroless/python3" \
      security.nonroot="true"