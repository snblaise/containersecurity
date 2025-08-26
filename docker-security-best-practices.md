# Docker Security Best Practices for AWS Container Security

This document outlines five critical Docker security best practices for building secure container images in regulated financial services environments. Each practice includes detailed explanations, implementation examples, and security rationale.

## 1. Use Minimal Base Images and Multi-Stage Builds

### Security Rationale
Minimal base images reduce the attack surface by eliminating unnecessary packages, libraries, and potential vulnerabilities. Multi-stage builds allow you to separate build dependencies from runtime dependencies, resulting in smaller, more secure final images.

### Implementation
- Use distroless images or scratch for static binaries
- Implement multi-stage builds to exclude build tools from final image
- Remove package managers and unnecessary utilities from production images

### Example
```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Production stage
FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=builder /app/main /
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/main"]
```

### Security Benefits
- Reduces image size by 80-90%
- Eliminates shell access and package managers
- Minimizes potential vulnerability exposure
- Prevents runtime package installation

## 2. Run Containers as Non-Root Users

### Security Rationale
Running containers as root provides unnecessary privileges that can be exploited if a container is compromised. Non-root execution follows the principle of least privilege and limits the impact of potential security breaches.

### Implementation
- Create dedicated non-root users with specific UIDs/GIDs
- Use UIDs > 1000 to avoid conflicts with system users
- Set appropriate file permissions for application files
- Configure proper ownership of application directories

### Example
```dockerfile
FROM alpine:3.18
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser
COPY --chown=appuser:appgroup app /usr/local/bin/app
RUN chmod +x /usr/local/bin/app
USER 1001:1001
ENTRYPOINT ["/usr/local/bin/app"]
```

### Security Benefits
- Prevents privilege escalation attacks
- Limits file system access to owned resources
- Reduces impact of container breakout attempts
- Aligns with Pod Security Standards restricted profile

## 3. Implement Read-Only Root Filesystem

### Security Rationale
A read-only root filesystem prevents malicious code from modifying system files, installing backdoors, or persisting changes. This immutable approach enhances container security by making runtime modifications impossible.

### Implementation
- Configure containers with read-only root filesystem
- Use tmpfs mounts for temporary file storage
- Create writable volumes only where necessary
- Ensure application supports read-only filesystem constraints

### Example
```dockerfile
FROM alpine:3.18
RUN adduser -D -u 1001 appuser
COPY --chown=appuser:appuser app /usr/local/bin/app
RUN chmod +x /usr/local/bin/app && \
    mkdir -p /tmp/app-cache && \
    chown appuser:appuser /tmp/app-cache
USER 1001
ENTRYPOINT ["/usr/local/bin/app"]
```

### Kubernetes Configuration
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    readOnlyRootFilesystem: true
  containers:
  - name: app
    volumeMounts:
    - name: tmp-volume
      mountPath: /tmp
  volumes:
  - name: tmp-volume
    emptyDir: {}
```

### Security Benefits
- Prevents runtime file system modifications
- Blocks malware persistence mechanisms
- Enhances forensic capabilities
- Supports immutable infrastructure principles

## 4. Drop Unnecessary Capabilities and Use Seccomp Profiles

### Security Rationale
Linux capabilities provide fine-grained privilege control beyond the traditional root/non-root model. Dropping unnecessary capabilities and applying seccomp profiles reduces the kernel attack surface and limits system call access.

### Implementation
- Drop all capabilities by default
- Add only required capabilities explicitly
- Use runtime/default seccomp profile
- Implement custom seccomp profiles for high-security environments

### Example
```dockerfile
FROM alpine:3.18
RUN adduser -D -u 1001 appuser
COPY --chown=appuser:appuser app /usr/local/bin/app
USER 1001
ENTRYPOINT ["/usr/local/bin/app"]
```

### Kubernetes Configuration
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      runAsNonRoot: true
      runAsUser: 1001
```

### Security Benefits
- Limits kernel functionality exposure
- Prevents privilege escalation
- Reduces system call attack surface
- Enhances runtime security monitoring

## 5. Scan Images for Vulnerabilities and Sign for Integrity

### Security Rationale
Vulnerability scanning identifies known security issues in container images, while image signing ensures integrity and authenticity. These practices are essential for supply chain security and regulatory compliance.

### Implementation
- Integrate vulnerability scanning in CI/CD pipelines
- Set vulnerability thresholds for build failures
- Implement image signing with cryptographic signatures
- Verify signatures before deployment

### CI/CD Integration Example
```yaml
# buildspec.yml for AWS CodeBuild
version: 0.2
phases:
  pre_build:
    commands:
      - echo Logging in to Amazon ECR...
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com
  build:
    commands:
      - echo Build started on `date`
      - docker build -t $IMAGE_REPO_NAME:$IMAGE_TAG .
      - docker tag $IMAGE_REPO_NAME:$IMAGE_TAG $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/$IMAGE_REPO_NAME:$IMAGE_TAG
  post_build:
    commands:
      - echo Build completed on `date`
      - echo Pushing the Docker image...
      - docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com/$IMAGE_REPO_NAME:$IMAGE_TAG
      - echo Scanning image for vulnerabilities...
      - aws ecr start-image-scan --repository-name $IMAGE_REPO_NAME --image-id imageTag=$IMAGE_TAG
```

### Security Benefits
- Identifies known vulnerabilities before deployment
- Prevents deployment of high-risk images
- Ensures image authenticity and integrity
- Supports compliance and audit requirements

## Implementation Examples

This repository includes several secure Dockerfile examples demonstrating these best practices:

### Base Image Templates
- `base-images/alpine-nonroot.Dockerfile` - Alpine Linux with non-root user configuration
- `base-images/ubuntu-nonroot.Dockerfile` - Ubuntu with security hardening
- `base-images/scratch-static.Dockerfile` - Minimal scratch image for static binaries

### Application Examples
- `examples/secure-multistage.Dockerfile` - Multi-stage Go application with comprehensive security
- `examples/go-static-secure.Dockerfile` - Static Go binary with scratch base
- `examples/python-secure.Dockerfile` - Python application with distroless runtime
- `examples/java-secure.Dockerfile` - Java application with distroless JRE

### Validation Tools
- `scripts/validate-docker-security.sh` - Automated security validation script

## Implementation Checklist

- [ ] Use minimal base images (distroless, scratch, or alpine)
- [ ] Implement multi-stage builds to reduce final image size
- [ ] Create and use non-root users with specific UIDs/GIDs (1001 recommended)
- [ ] Configure read-only root filesystem with tmpfs mounts
- [ ] Drop all capabilities and use seccomp profiles
- [ ] Integrate vulnerability scanning in CI/CD pipelines
- [ ] Implement image signing for supply chain security
- [ ] Set vulnerability thresholds for build failures (0 critical, ≤5 high)
- [ ] Add security labels for metadata and compliance
- [ ] Configure health checks for container monitoring
- [ ] Use non-privileged ports (>1024) for application services
- [ ] Validate security configurations using provided scripts
- [ ] Document security assumptions and constraints
- [ ] Test security configurations in staging environments

## Security Assumptions

1. **Base Image Trust**: Assumes base images from official repositories are regularly updated and maintained
2. **Build Environment**: Assumes CI/CD build environment is secure and isolated
3. **Registry Security**: Assumes container registry (ECR) is properly configured with access controls
4. **Network Security**: Assumes network policies and firewalls provide additional layers of protection
5. **Monitoring**: Assumes runtime security monitoring is in place to detect anomalous behavior

## Configuration Locations and Security Effects

| Configuration | Location | Security Effect |
|---------------|----------|-----------------|
| Non-root user | Dockerfile USER directive | Prevents privilege escalation |
| Read-only filesystem | Pod securityContext | Prevents runtime modifications |
| Capability dropping | Container securityContext | Limits kernel access |
| Seccomp profile | Pod securityContext | Restricts system calls |
| Vulnerability scanning | CI/CD pipeline | Prevents vulnerable deployments |
| Image signing | Build and admission policies | Ensures image integrity |

This documentation provides the foundation for implementing secure Docker practices in AWS container environments, supporting both security requirements and regulatory compliance needs.