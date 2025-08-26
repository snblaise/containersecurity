# Kubernetes NetworkPolicy Configurations

This directory contains comprehensive NetworkPolicy configurations for implementing network security in Amazon EKS clusters. These policies follow the principle of least privilege and implement defense-in-depth network security.

## Overview

NetworkPolicies control traffic flow at the IP address or port level (OSI layer 3 or 4). They specify how groups of pods are allowed to communicate with each other and other network endpoints.

## Policy Categories

### 1. Default Deny Policies

**Purpose**: Establish secure baseline by denying all traffic by default

- `default-deny-all.yaml` - Denies all ingress and egress traffic
- `default-deny-ingress.yaml` - Denies all ingress traffic, allows egress

**Usage**:
```bash
# Apply default deny to a namespace
kubectl apply -f default-deny-all.yaml -n production
```

### 2. Namespace Isolation Policies

**Purpose**: Prevent cross-namespace communication while allowing intra-namespace traffic

- `namespace-isolation.yaml` - Isolates production and staging namespaces

**Features**:
- Allows traffic only within the same namespace
- Permits DNS resolution (UDP port 53)
- Allows HTTPS egress for external APIs (TCP port 443)

### 3. Application-Specific Policies

**Purpose**: Fine-grained control for web applications and microservices

#### Web Application Policies (`web-app-policies.yaml`)
- **Frontend Policy**: Allows ingress from load balancers, egress to backend
- **Backend API Policy**: Allows ingress from frontend, egress to database
- **Database Policy**: Restricts ingress to backend services only

#### Microservices Policies (`microservices-policies.yaml`)
- **User Service**: Handles authentication with controlled access
- **Order Service**: Processes orders with multi-service communication
- **Payment Service**: Highly restricted for PCI compliance

### 4. System Policies

**Purpose**: Enable cluster operations and monitoring

- `system-policies.yaml` - Policies for kube-system, monitoring, and AWS controllers

## Prerequisites

1. **CNI Plugin**: Ensure your EKS cluster uses a CNI that supports NetworkPolicies:
   - Amazon VPC CNI with Calico
   - Cilium
   - Weave Net

2. **Namespace Labels**: Label your namespaces for policy selectors:
```bash
kubectl label namespace production name=production
kubectl label namespace staging name=staging
kubectl label namespace kube-system name=kube-system
kubectl label namespace monitoring name=monitoring
```

## Deployment Strategy

### Phase 1: Preparation
1. Audit existing network traffic patterns
2. Label all pods and namespaces appropriately
3. Test policies in a staging environment

### Phase 2: Gradual Rollout
1. Start with `default-deny-ingress` (less disruptive)
2. Apply application-specific allow policies
3. Gradually move to `default-deny-all`
4. Monitor and adjust based on application needs

### Phase 3: Full Implementation
```bash
# 1. Apply namespace isolation
kubectl apply -f namespace-isolation.yaml

# 2. Apply default deny policies
kubectl apply -f default-deny-all.yaml -n production
kubectl apply -f default-deny-all.yaml -n staging

# 3. Apply application policies
kubectl apply -f web-app-policies.yaml
kubectl apply -f microservices-policies.yaml

# 4. Apply system policies
kubectl apply -f system-policies.yaml
```

## Validation and Testing

### Test Network Connectivity
```bash
# Test pod-to-pod communication
kubectl exec -it frontend-pod -- curl backend-service:3000

# Test external connectivity
kubectl exec -it backend-pod -- curl https://api.external-service.com

# Test blocked communication (should fail)
kubectl exec -it database-pod -- curl frontend-service:8080
```

### Monitor Policy Violations
```bash
# Check for denied connections in CNI logs
kubectl logs -n kube-system -l k8s-app=calico-node | grep "denied"

# Monitor NetworkPolicy events
kubectl get events --field-selector reason=NetworkPolicyViolation
```

## Common Patterns

### Allow DNS Resolution
Always include DNS egress in your policies:
```yaml
egress:
- to: []
  ports:
  - protocol: UDP
    port: 53
```

### Allow Health Checks
For load balancer health checks:
```yaml
ingress:
- from: []  # Allow from any source
  ports:
  - protocol: TCP
    port: 8080
```

### Service Mesh Integration
For Istio/Linkerd sidecars:
```yaml
ingress:
- from:
  - podSelector:
      matchLabels:
        app: istio-proxy
  ports:
  - protocol: TCP
    port: 15090
```

## Troubleshooting

### Common Issues

1. **DNS Resolution Fails**
   - Ensure UDP port 53 egress is allowed
   - Check if CoreDNS pods are accessible

2. **Health Check Failures**
   - Verify load balancer can reach health check endpoints
   - Check if kube-system namespace has required access

3. **Service Discovery Issues**
   - Ensure intra-namespace communication is allowed
   - Verify service account tokens can be mounted

### Debugging Commands
```bash
# Check applied policies
kubectl get networkpolicy -A

# Describe specific policy
kubectl describe networkpolicy frontend-policy -n production

# Test connectivity with netshoot
kubectl run netshoot --rm -it --image nicolaka/netshoot -- /bin/bash
```

## Security Considerations

1. **Default Deny**: Always start with default deny policies
2. **Least Privilege**: Only allow necessary communication paths
3. **Regular Audits**: Review and update policies regularly
4. **Monitoring**: Implement logging for policy violations
5. **Testing**: Validate policies don't break legitimate traffic

## Integration with AWS Security

These NetworkPolicies complement AWS security features:
- **Security Groups for Pods**: Node-level network controls
- **AWS Network Firewall**: VPC-level egress filtering
- **VPC Flow Logs**: Network traffic monitoring
- **GuardDuty**: Threat detection for network anomalies

## Compliance Alignment

These policies support compliance with:
- **CIS Kubernetes Benchmark**: Network segmentation controls
- **NIST Cybersecurity Framework**: Network security controls
- **SOC 2**: Network access controls and monitoring
- **PCI DSS**: Network segmentation for payment processing