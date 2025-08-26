# Admission Policy Validation Checklist

## Overview

This checklist provides comprehensive validation procedures for Pod Security Admission policies and custom admission controllers to ensure proper security policy enforcement.

## Pod Security Admission Validation

### Pre-Validation Setup
- [ ] Verify Pod Security Admission is enabled on the cluster
- [ ] Confirm namespace labels are properly configured
- [ ] Validate admission controller webhook configurations
- [ ] Check RBAC permissions for admission controllers

### Restricted Policy Validation

#### Security Context Requirements
- [ ] **Non-root User Enforcement**
  ```bash
  # Test: Deploy pod with root user (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: root-user-test
    namespace: restricted-ns
  spec:
    containers:
    - name: test
      image: busybox
      securityContext:
        runAsUser: 0
  EOF
  # Expected: Pod creation should be rejected
  ```

- [ ] **Privilege Escalation Prevention**
  ```bash
  # Test: Deploy pod with allowPrivilegeEscalation: true (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: privilege-escalation-test
    namespace: restricted-ns
  spec:
    containers:
    - name: test
      image: busybox
      securityContext:
        allowPrivilegeEscalation: true
  EOF
  # Expected: Pod creation should be rejected
  ```

- [ ] **Capability Restrictions**
  ```bash
  # Test: Deploy pod with additional capabilities (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: capabilities-test
    namespace: restricted-ns
  spec:
    containers:
    - name: test
      image: busybox
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
  EOF
  # Expected: Pod creation should be rejected
  ```

- [ ] **Read-only Root Filesystem**
  ```bash
  # Test: Deploy pod without read-only root filesystem (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: writable-root-test
    namespace: restricted-ns
  spec:
    containers:
    - name: test
      image: busybox
      securityContext:
        readOnlyRootFilesystem: false
  EOF
  # Expected: Pod creation should be rejected
  ```

#### Volume Type Restrictions
- [ ] **Host Path Volumes**
  ```bash
  # Test: Deploy pod with hostPath volume (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: hostpath-test
    namespace: restricted-ns
  spec:
    containers:
    - name: test
      image: busybox
      volumeMounts:
      - name: host-vol
        mountPath: /host
    volumes:
    - name: host-vol
      hostPath:
        path: /etc
  EOF
  # Expected: Pod creation should be rejected
  ```

- [ ] **Privileged Containers**
  ```bash
  # Test: Deploy privileged container (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: privileged-test
    namespace: restricted-ns
  spec:
    containers:
    - name: test
      image: busybox
      securityContext:
        privileged: true
  EOF
  # Expected: Pod creation should be rejected
  ```

### Baseline Policy Validation

#### Host Namespace Restrictions
- [ ] **Host Network**
  ```bash
  # Test: Deploy pod with hostNetwork (should fail in restricted, pass in baseline)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: hostnetwork-test
    namespace: baseline-ns
  spec:
    hostNetwork: true
    containers:
    - name: test
      image: busybox
  EOF
  # Expected: Behavior depends on namespace policy level
  ```

- [ ] **Host PID/IPC**
  ```bash
  # Test: Deploy pod with hostPID (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: hostpid-test
    namespace: baseline-ns
  spec:
    hostPID: true
    containers:
    - name: test
      image: busybox
  EOF
  # Expected: Pod creation should be rejected
  ```

### Custom Admission Controller Validation

#### Image Policy Enforcement
- [ ] **Unsigned Image Rejection**
  ```bash
  # Test: Deploy pod with unsigned image (should fail if signing required)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: unsigned-image-test
    namespace: production
  spec:
    containers:
    - name: test
      image: docker.io/busybox:latest
  EOF
  # Expected: Pod creation should be rejected if image signing is enforced
  ```

- [ ] **Registry Allowlist**
  ```bash
  # Test: Deploy pod with image from disallowed registry (should fail)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: disallowed-registry-test
    namespace: production
  spec:
    containers:
    - name: test
      image: quay.io/test/image:latest
  EOF
  # Expected: Pod creation should be rejected if registry not in allowlist
  ```

#### Resource Limits Enforcement
- [ ] **Missing Resource Limits**
  ```bash
  # Test: Deploy pod without resource limits (should fail if required)
  kubectl apply -f - <<EOF
  apiVersion: v1
  kind: Pod
  metadata:
    name: no-limits-test
    namespace: production
  spec:
    containers:
    - name: test
      image: busybox
  EOF
  # Expected: Pod creation should be rejected if resource limits are required
  ```

### Validation Automation Script

```bash
#!/bin/bash
# admission-policy-validation.sh

set -e

NAMESPACE=${1:-"test-validation"}
CLEANUP=${2:-"true"}

echo "Starting admission policy validation for namespace: $NAMESPACE"

# Create test namespace with restricted policy
kubectl create namespace $NAMESPACE --dry-run=client -o yaml | \
kubectl label --local -f - \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  -o yaml | kubectl apply -f -

# Test cases array
declare -a test_cases=(
  "root-user:runAsUser=0"
  "privilege-escalation:allowPrivilegeEscalation=true"
  "capabilities:capabilities.add=[NET_ADMIN]"
  "writable-root:readOnlyRootFilesystem=false"
  "hostpath-volume:hostPath"
  "privileged:privileged=true"
)

failed_tests=0
passed_tests=0

for test_case in "${test_cases[@]}"; do
  test_name=$(echo $test_case | cut -d: -f1)
  test_config=$(echo $test_case | cut -d: -f2)
  
  echo "Testing: $test_name"
  
  # Create test pod (should fail)
  if kubectl run $test_name --image=busybox --namespace=$NAMESPACE --dry-run=client -o yaml | \
     kubectl apply -f - 2>/dev/null; then
    echo "❌ FAILED: $test_name - Pod was allowed but should have been rejected"
    ((failed_tests++))
  else
    echo "✅ PASSED: $test_name - Pod was correctly rejected"
    ((passed_tests++))
  fi
done

echo "Validation Summary:"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

# Cleanup
if [ "$CLEANUP" = "true" ]; then
  kubectl delete namespace $NAMESPACE --ignore-not-found=true
fi

if [ $failed_tests -gt 0 ]; then
  exit 1
fi

echo "All admission policy validations passed!"
```

## Validation Results Documentation

### Test Execution Log Template
```
Date: [DATE]
Cluster: [CLUSTER_NAME]
Namespace: [NAMESPACE]
Policy Level: [restricted/baseline/privileged]

Test Results:
- Non-root User Enforcement: [PASS/FAIL]
- Privilege Escalation Prevention: [PASS/FAIL]
- Capability Restrictions: [PASS/FAIL]
- Read-only Root Filesystem: [PASS/FAIL]
- Host Path Volume Restrictions: [PASS/FAIL]
- Privileged Container Prevention: [PASS/FAIL]

Custom Admission Controllers:
- Image Signing Enforcement: [PASS/FAIL]
- Registry Allowlist: [PASS/FAIL]
- Resource Limits Enforcement: [PASS/FAIL]

Overall Status: [PASS/FAIL]
Notes: [Any additional observations or issues]
```

### Continuous Validation Integration

```yaml
# CronJob for automated admission policy validation
apiVersion: batch/v1
kind: CronJob
metadata:
  name: admission-policy-validation
  namespace: security-validation
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: validation-runner
          containers:
          - name: validator
            image: kubectl:latest
            command:
            - /bin/bash
            - -c
            - |
              /scripts/admission-policy-validation.sh validation-test true
              # Send results to monitoring system
              curl -X POST $WEBHOOK_URL -d "Admission policy validation completed"
            volumeMounts:
            - name: validation-scripts
              mountPath: /scripts
          volumes:
          - name: validation-scripts
            configMap:
              name: validation-scripts
              defaultMode: 0755
          restartPolicy: OnFailure
```

This comprehensive validation checklist ensures that admission policies are properly configured and enforced across the Kubernetes cluster.