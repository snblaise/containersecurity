# Image Signing Enforcement Verification

## Overview

This document provides comprehensive procedures for validating image signing enforcement across the container deployment pipeline, from build-time signing through runtime verification.

## Image Signing Validation Framework

### Pre-Verification Setup
- [ ] Verify AWS Signer service configuration
- [ ] Confirm signing keys and certificates are properly configured
- [ ] Validate admission controller policies for signature verification
- [ ] Check RBAC permissions for signing and verification processes

### Build-Time Signing Verification

#### AWS Signer Integration
- [ ] **Signing Profile Configuration**
  ```bash
  # Verify signing profile exists and is active
  aws signer describe-signing-job --job-id $SIGNING_JOB_ID
  
  # Expected output should show successful signing status
  {
    "jobId": "12345678-1234-1234-1234-123456789012",
    "source": {
      "s3": {
        "bucketName": "my-signing-bucket",
        "key": "unsigned-image.tar"
      }
    },
    "signingMaterial": {
      "certificateArn": "arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    },
    "platformId": "AWSLambda-SHA256-ARM64",
    "profileName": "container_signing_profile",
    "status": "Succeeded"
  }
  ```

- [ ] **CodeBuild Integration Verification**
  ```yaml
  # buildspec.yml signing integration
  version: 0.2
  phases:
    post_build:
      commands:
        # Build and tag image
        - docker build -t $IMAGE_URI .
        - docker push $IMAGE_URI
        
        # Create signing payload
        - aws ecr get-download-url-for-layer --repository-name $REPO_NAME --layer-digest $LAYER_DIGEST
        
        # Sign image using AWS Signer
        - aws signer start-signing-job \
            --source s3={bucketName=$SIGNING_BUCKET,key=$IMAGE_TAR} \
            --destination s3={bucketName=$SIGNED_BUCKET,key=$SIGNED_IMAGE_TAR} \
            --profile-name $SIGNING_PROFILE
        
        # Verify signing completed successfully
        - SIGNING_JOB_ID=$(aws signer list-signing-jobs --status Succeeded --query 'jobs[0].jobId' --output text)
        - aws signer describe-signing-job --job-id $SIGNING_JOB_ID
  ```

#### Cosign Integration (Alternative)
- [ ] **Cosign Signing Verification**
  ```bash
  # Sign image with cosign
  cosign sign --key cosign.key $IMAGE_URI
  
  # Verify signature exists
  cosign verify --key cosign.pub $IMAGE_URI
  
  # Expected output:
  # Verification for 123456789012.dkr.ecr.us-west-2.amazonaws.com/app:latest --
  # The following checks were performed on each of these signatures:
  #   - The cosign claims were validated
  #   - The signatures were verified against the specified public key
  ```

### Runtime Signature Verification

#### Admission Controller Validation
- [ ] **Kyverno Policy Enforcement**
  ```yaml
  # Test unsigned image rejection
  apiVersion: kyverno.io/v1
  kind: ClusterPolicy
  metadata:
    name: verify-image-signatures
  spec:
    validationFailureAction: enforce
    background: false
    rules:
    - name: verify-signature
      match:
        any:
        - resources:
            kinds:
            - Pod
      verifyImages:
      - imageReferences:
        - "*"
        attestors:
        - entries:
          - keys:
              publicKeys: |-
                -----BEGIN PUBLIC KEY-----
                [PUBLIC_KEY_CONTENT]
                -----END PUBLIC KEY-----
  ```

- [ ] **Test Unsigned Image Deployment**
  ```bash
  # Attempt to deploy unsigned image (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: unsigned-image-test
    namespace: production
  spec:
    containers:
    - name: app
      image: docker.io/busybox:unsigned
  EOF
  
  # Expected: Pod creation should be rejected with signature verification error
  ```

- [ ] **Test Signed Image Deployment**
  ```bash
  # Deploy properly signed image (should succeed)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: signed-image-test
    namespace: production
  spec:
    containers:
    - name: app
      image: 123456789012.dkr.ecr.us-west-2.amazonaws.com/app:signed-v1.0.0
  EOF
  
  # Expected: Pod should be created successfully
  ```

#### Gatekeeper Policy Validation
- [ ] **OPA Gatekeeper Constraint**
  ```yaml
  apiVersion: templates.gatekeeper.sh/v1beta1
  kind: ConstraintTemplate
  metadata:
    name: requireimagesignature
  spec:
    crd:
      spec:
        names:
          kind: RequireImageSignature
        validation:
          properties:
            exemptImages:
              type: array
              items:
                type: string
    targets:
      - target: admission.k8s.gatekeeper.sh
        rego: |
          package requireimagesignature
          
          violation[{"msg": msg}] {
            container := input.review.object.spec.containers[_]
            not is_exempt(container.image)
            not has_valid_signature(container.image)
            msg := sprintf("Image %v must be signed", [container.image])
          }
          
          is_exempt(image) {
            exempt := input.parameters.exemptImages[_]
            startswith(image, exempt)
          }
          
          has_valid_signature(image) {
            # Integration with signature verification service
            # This would call external verification service
            false  # Placeholder - implement actual verification logic
          }
  ```

### Signature Verification Automation

#### Verification Script
```bash
#!/bin/bash
# image-signing-verification.sh

set -e

IMAGE_URI=${1:-""}
VERIFICATION_METHOD=${2:-"cosign"}  # cosign or aws-signer
PUBLIC_KEY_PATH=${3:-"cosign.pub"}

if [ -z "$IMAGE_URI" ]; then
  echo "Usage: $0 <image-uri> [verification-method] [public-key-path]"
  exit 1
fi

echo "Verifying image signature for: $IMAGE_URI"
echo "Verification method: $VERIFICATION_METHOD"

case $VERIFICATION_METHOD in
  "cosign")
    echo "Using Cosign for verification..."
    if cosign verify --key $PUBLIC_KEY_PATH $IMAGE_URI; then
      echo "✅ Image signature verification PASSED"
      exit 0
    else
      echo "❌ Image signature verification FAILED"
      exit 1
    fi
    ;;
  
  "aws-signer")
    echo "Using AWS Signer for verification..."
    # Extract image digest
    IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' $IMAGE_URI | cut -d'@' -f2)
    
    # Query AWS Signer for signature
    SIGNATURE_INFO=$(aws signer list-signing-jobs \
      --status Succeeded \
      --query "jobs[?contains(source.s3.key, '$IMAGE_DIGEST')]" \
      --output json)
    
    if [ "$(echo $SIGNATURE_INFO | jq length)" -gt 0 ]; then
      echo "✅ Image signature verification PASSED"
      echo "Signature details: $SIGNATURE_INFO"
      exit 0
    else
      echo "❌ Image signature verification FAILED - No valid signature found"
      exit 1
    fi
    ;;
  
  *)
    echo "❌ Unknown verification method: $VERIFICATION_METHOD"
    echo "Supported methods: cosign, aws-signer"
    exit 1
    ;;
esac
```

#### Continuous Verification Monitoring
```yaml
# CronJob for continuous signature verification
apiVersion: batch/v1
kind: CronJob
metadata:
  name: image-signature-verification
  namespace: security-validation
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: signature-verifier
          containers:
          - name: verifier
            image: signature-verification:latest
            command:
            - /bin/bash
            - -c
            - |
              # Get all running images in cluster
              kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u > /tmp/running-images.txt
              
              # Verify each image signature
              failed_verifications=0
              while read image; do
                echo "Verifying: $image"
                if ! /scripts/image-signing-verification.sh "$image" cosign /keys/cosign.pub; then
                  echo "ALERT: Unsigned image detected: $image"
                  ((failed_verifications++))
                fi
              done < /tmp/running-images.txt
              
              # Report results
              if [ $failed_verifications -gt 0 ]; then
                echo "CRITICAL: $failed_verifications unsigned images detected in cluster"
                # Send alert to monitoring system
                curl -X POST $ALERT_WEBHOOK_URL -d "{\"alert\": \"Unsigned images detected\", \"count\": $failed_verifications}"
                exit 1
              else
                echo "All running images have valid signatures"
              fi
            volumeMounts:
            - name: verification-scripts
              mountPath: /scripts
            - name: signing-keys
              mountPath: /keys
              readOnly: true
          volumes:
          - name: verification-scripts
            configMap:
              name: verification-scripts
              defaultMode: 0755
          - name: signing-keys
            secret:
              secretName: signing-public-keys
          restartPolicy: OnFailure
```

### Emergency Bypass Procedures

#### Temporary Signature Bypass
```yaml
# Emergency bypass for critical security patches
apiVersion: kyverno.io/v1
kind: PolicyException
metadata:
  name: emergency-patch-bypass
  namespace: production
spec:
  exceptions:
  - policyName: verify-image-signatures
    ruleNames:
    - verify-signature
  match:
  - any:
    - resources:
        kinds:
        - Pod
        names:
        - emergency-patch-*
        namespaces:
        - production
  # Auto-expire after 24 hours
  validUntil: "2024-01-01T23:59:59Z"
```

### Verification Metrics and Reporting

#### Key Performance Indicators
- **Signature Verification Success Rate**: Percentage of images with valid signatures
- **Unsigned Image Detection Time**: Time to detect unsigned images in cluster
- **Policy Violation Response Time**: Time to respond to signature policy violations
- **Emergency Bypass Usage**: Frequency and duration of signature bypass procedures

#### Monitoring Dashboard Queries
```promql
# Signature verification success rate
(
  sum(rate(image_signature_verification_success_total[5m])) /
  sum(rate(image_signature_verification_total[5m]))
) * 100

# Unsigned images in cluster
sum(unsigned_images_detected_total)

# Policy violations per hour
rate(signature_policy_violations_total[1h])
```

### Troubleshooting Common Issues

#### Signature Verification Failures
1. **Invalid Public Key**
   - Verify public key format and encoding
   - Check key rotation and certificate expiration
   - Validate key distribution to verification systems

2. **Network Connectivity Issues**
   - Test connectivity to signing service endpoints
   - Verify firewall and security group configurations
   - Check DNS resolution for signing services

3. **Admission Controller Errors**
   - Review admission controller logs for detailed error messages
   - Verify webhook configurations and certificates
   - Check RBAC permissions for admission controllers

#### Performance Optimization
- Implement signature caching to reduce verification latency
- Use parallel verification for multiple images
- Configure appropriate timeout values for verification processes
- Monitor resource usage of verification components

This comprehensive verification framework ensures that image signing enforcement is properly implemented and continuously validated across the container deployment pipeline.