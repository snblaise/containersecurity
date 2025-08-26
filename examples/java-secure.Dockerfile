# Secure Java Application Dockerfile
# Demonstrates security hardening for Java applications

# Build Stage
FROM eclipse-temurin:17-jdk-alpine AS builder

# Create non-root user for build
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

WORKDIR /app

# Copy build files
COPY --chown=appuser:appgroup pom.xml .
COPY --chown=appuser:appgroup src ./src

# Switch to non-root user for build
USER appuser

# Build application
RUN ./mvnw clean package -DskipTests

# Production Stage - Distroless Java runtime
FROM gcr.io/distroless/java17-debian11:nonroot AS production

# Copy only the JAR file from builder stage
COPY --from=builder --chown=nonroot:nonroot /app/target/*.jar /app/application.jar

# Use distroless nonroot user
USER nonroot

# Expose non-privileged port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/bin/java", "-cp", "/app/application.jar", "com.company.HealthCheck"]

# Start application with security flags
ENTRYPOINT ["/usr/bin/java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-Dspring.profiles.active=production", \
    "-jar", "/app/application.jar"]

# Security metadata
LABEL security.scan="required" \
      security.signature="required" \
      base.image="distroless/java17" \
      security.nonroot="true"