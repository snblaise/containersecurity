# Container Security Incident Response Procedures

## Overview

This document provides comprehensive incident response procedures for container security events, including detection, containment, investigation, and recovery processes.

## Incident Classification

### Severity Levels

#### Critical (P0)
- Active container compromise with data exfiltration
- Privilege escalation to cluster admin level
- Widespread malware deployment across multiple nodes
- Complete cluster compromise or unavailability

#### High (P1)
- Container breakout to host system
- Unauthorized access to sensitive secrets or data
- Deployment of unsigned or malicious images
- Network policy bypass with lateral movement

#### Medium (P2)
- Policy violations without immediate security impact
- Vulnerable images deployed but not exploited
- Configuration drift from security baselines
- Failed security scans or compliance checks

#### Low (P3)
- Minor policy violations
- Informational security alerts
- Routine vulnerability notifications
- Documentation or process improvements needed

## Incident Response Procedures

### 1. Container Compromise Response

#### Immediate Response (0-15 minutes)
- [ ] **Alert Acknowledgment**
  ```bash
  # Acknowledge alert in monitoring system
  aws cloudwatch put-metric-data \
    --namespace "Security/Incidents" \
    --metric-data MetricName=IncidentAcknowledged,Value=1,Unit=Count
  ```

- [ ] **Initial Assessment**
  ```bash
  # Identify compromised pod(s)
  kubectl get pods --all-namespaces -l security.incident=true
  
  # Check pod status and recent events
  kubectl describe pod $COMPROMISED_POD -n $NAMESPACE
  
  # Review recent container logs
  kubectl logs $COMPROMISED_POD -n $NAMESPACE --tail=100
  ```

- [ ] **Immediate Isolation**
  ```bash
  # Apply network isolation policy
  kubectl apply -f - <<EOF
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: isolate-compromised-pod
    namespace: $NAMESPACE
  spec:
    podSelector:
      matchLabels:
        app: $COMPROMISED_APP
    policyTypes:
    - Ingress
    - Egress
    # No ingress or egress rules = complete isolation
  EOF
  ```

#### Investigation Phase (15-60 minutes)
- [ ] **Evidence Collection**
  ```bash
  # Capture pod manifest
  kubectl get pod $COMPROMISED_POD -n $NAMESPACE -o yaml > evidence/pod-manifest.yaml
  
  # Export container logs
  kubectl logs $COMPROMISED_POD -n $NAMESPACE --previous > evidence/container-logs.txt
  
  # Capture node information
  kubectl describe node $NODE_NAME > evidence/node-info.txt
  
  # Export security events
  kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' > evidence/security-events.txt
  ```

- [ ] **Forensic Analysis**
  ```bash
  # Check for privilege escalation
  kubectl auth can-i --list --as=system:serviceaccount:$NAMESPACE:$SERVICE_ACCOUNT
  
  # Review RBAC permissions
  kubectl describe rolebinding,clusterrolebinding -n $NAMESPACE
  
  # Analyze network connections
  kubectl exec $COMPROMISED_POD -n $NAMESPACE -- netstat -tulpn
  ```

- [ ] **Impact Assessment**
  ```bash
  # Check for lateral movement
  kubectl get pods --all-namespaces -o wide | grep $NODE_NAME
  
  # Review GuardDuty findings
  aws guardduty list-findings --detector-id $DETECTOR_ID \
    --finding-criteria '{"Criterion":{"service.resourceRole":{"Eq":["TARGET"]}}}'
  
  # Check CloudTrail for suspicious API calls
  aws logs filter-log-events \
    --log-group-name /aws/eks/$CLUSTER_NAME/cluster \
    --start-time $(date -d '1 hour ago' +%s)000 \
    --filter-pattern '{ $.sourceIPAddress != "10.*" }'
  ```

#### Containment Phase (1-4 hours)
- [ ] **Pod Termination**
  ```bash
  # Gracefully terminate compromised pod
  kubectl delete pod $COMPROMISED_POD -n $NAMESPACE --grace-period=30
  
  # Force termination if necessary
  kubectl delete pod $COMPROMISED_POD -n $NAMESPACE --force --grace-period=0
  ```

- [ ] **Node Isolation** (if compromise extends to node)
  ```bash
  # Cordon node to prevent new pod scheduling
  kubectl cordon $NODE_NAME
  
  # Drain node of all pods
  kubectl drain $NODE_NAME --ignore-daemonsets --delete-emptydir-data
  
  # Apply node-level network restrictions
  aws ec2 modify-instance-attribute \
    --instance-id $INSTANCE_ID \
    --groups sg-isolated-node
  ```

- [ ] **Secret Rotation**
  ```bash
  # Rotate potentially compromised secrets
  aws secretsmanager update-secret \
    --secret-id $SECRET_ARN \
    --secret-string '{"username":"newuser","password":"newpassword"}'
  
  # Update Kubernetes secrets
  kubectl create secret generic $SECRET_NAME \
    --from-literal=username=newuser \
    --from-literal=password=newpassword \
    --dry-run=client -o yaml | kubectl apply -f -
  ```

### 2. Vulnerability Response Procedures

#### Critical Vulnerability Response
- [ ] **Vulnerability Assessment**
  ```bash
  # Query Inspector for vulnerability details
  aws inspector2 list-findings \
    --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}'
  
  # Check affected images
  aws ecr describe-image-scan-findings \
    --repository-name $REPO_NAME \
    --image-id imageTag=$TAG
  ```

- [ ] **Impact Analysis**
  ```bash
  # Find pods using vulnerable images
  kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep $VULNERABLE_IMAGE
  
  # Check deployment configurations
  kubectl get deployments --all-namespaces -o yaml | grep -A5 -B5 $VULNERABLE_IMAGE
  ```

- [ ] **Emergency Patching**
  ```bash
  # Build patched image
  docker build -t $PATCHED_IMAGE:$NEW_TAG .
  docker push $PATCHED_IMAGE:$NEW_TAG
  
  # Update deployments with patched image
  kubectl set image deployment/$DEPLOYMENT_NAME container=$PATCHED_IMAGE:$NEW_TAG -n $NAMESPACE
  
  # Verify rollout status
  kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE
  ```

### 3. Policy Violation Response

#### Admission Policy Violations
- [ ] **Violation Detection**
  ```bash
  # Check admission controller logs
  kubectl logs -n kyverno-system deployment/kyverno-admission-controller
  
  # Review policy violation events
  kubectl get events --all-namespaces --field-selector reason=PolicyViolation
  ```

- [ ] **Remediation Actions**
  ```bash
  # Update non-compliant resources
  kubectl patch pod $POD_NAME -n $NAMESPACE -p '{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65534}}}'
  
  # Apply corrective policies
  kubectl apply -f security-policies/corrective-policies.yaml
  ```

### 4. Network Security Incidents

#### Unauthorized Network Access
- [ ] **Traffic Analysis**
  ```bash
  # Check VPC Flow Logs
  aws logs filter-log-events \
    --log-group-name /aws/vpc/flowlogs \
    --filter-pattern '[srcaddr != "10.*", dstaddr != "10.*"]'
  
  # Review GuardDuty network findings
  aws guardduty get-findings \
    --detector-id $DETECTOR_ID \
    --finding-ids $FINDING_ID
  ```

- [ ] **Network Isolation**
  ```bash
  # Apply emergency network policies
  kubectl apply -f - <<EOF
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: emergency-isolation
    namespace: $NAMESPACE
  spec:
    podSelector: {}
    policyTypes:
    - Ingress
    - Egress
    egress:
    - to: []
      ports:
      - protocol: TCP
        port: 53
      - protocol: UDP
        port: 53
  EOF
  ```

## Escalation Procedures

### Internal Escalation Matrix

| Severity | Initial Response | Escalation Time | Escalation Target |
|----------|------------------|-----------------|-------------------|
| P0 | Security Team | Immediate | CISO, CTO |
| P1 | Security Team | 30 minutes | Security Manager |
| P2 | Security Team | 2 hours | Team Lead |
| P3 | Security Team | Next business day | Team Lead |

### External Escalation
- [ ] **Law Enforcement** (for criminal activity)
- [ ] **Regulatory Bodies** (for compliance violations)
- [ ] **AWS Support** (for platform-related issues)
- [ ] **Vendor Support** (for third-party tool issues)

## Communication Templates

### Initial Incident Notification
```
SUBJECT: [P0/P1/P2/P3] Container Security Incident - [Brief Description]

Incident Details:
- Incident ID: INC-YYYY-MM-DD-XXXX
- Severity: [P0/P1/P2/P3]
- Detection Time: [TIMESTAMP]
- Affected Systems: [CLUSTER/NAMESPACE/PODS]
- Initial Assessment: [BRIEF DESCRIPTION]

Immediate Actions Taken:
- [ACTION 1]
- [ACTION 2]
- [ACTION 3]

Next Steps:
- [PLANNED ACTION 1]
- [PLANNED ACTION 2]

Incident Commander: [NAME]
Next Update: [TIMESTAMP]
```

### Status Update Template
```
SUBJECT: [UPDATE] Container Security Incident - [Incident ID]

Status Update - [TIMESTAMP]

Current Status: [INVESTIGATING/CONTAINED/RESOLVED]

Progress Since Last Update:
- [PROGRESS ITEM 1]
- [PROGRESS ITEM 2]

Current Actions:
- [CURRENT ACTION 1]
- [CURRENT ACTION 2]

Impact Assessment:
- Affected Services: [LIST]
- Business Impact: [DESCRIPTION]
- Customer Impact: [DESCRIPTION]

Next Update: [TIMESTAMP]
```

## Recovery Procedures

### Service Restoration
- [ ] **Clean Image Deployment**
  ```bash
  # Deploy known-good images
  kubectl set image deployment/$DEPLOYMENT_NAME container=$CLEAN_IMAGE:$TAG -n $NAMESPACE
  
  # Verify deployment health
  kubectl get pods -n $NAMESPACE -l app=$APP_NAME
  kubectl logs -n $NAMESPACE -l app=$APP_NAME --tail=50
  ```

- [ ] **Configuration Validation**
  ```bash
  # Validate security configurations
  ./validation-framework/admission-policy-validation.sh $NAMESPACE
  
  # Check network policies
  kubectl get networkpolicies -n $NAMESPACE
  
  # Verify RBAC settings
  kubectl auth can-i --list --as=system:serviceaccount:$NAMESPACE:$SERVICE_ACCOUNT
  ```

### Post-Incident Activities
- [ ] **Root Cause Analysis**
- [ ] **Lessons Learned Documentation**
- [ ] **Security Control Updates**
- [ ] **Process Improvements**
- [ ] **Training Updates**

## Automation and Integration

### Automated Response Actions
```yaml
# Lambda function for automated incident response
import boto3
import json

def lambda_handler(event, context):
    # Parse GuardDuty finding
    finding = json.loads(event['Records'][0]['Sns']['Message'])
    
    if finding['severity'] >= 7.0:  # High/Critical severity
        # Trigger automated isolation
        isolate_compromised_resource(finding)
        
        # Notify incident response team
        send_incident_notification(finding)
        
        # Create incident ticket
        create_incident_ticket(finding)
    
    return {'statusCode': 200}

def isolate_compromised_resource(finding):
    # Implementation for automated isolation
    pass

def send_incident_notification(finding):
    # Implementation for notifications
    pass

def create_incident_ticket(finding):
    # Implementation for ticket creation
    pass
```

### Monitoring Integration
```yaml
# CloudWatch alarm for security incidents
Resources:
  SecurityIncidentAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ContainerSecurityIncident
      AlarmDescription: Alert on container security incidents
      MetricName: SecurityIncidents
      Namespace: Security/Container
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SecurityIncidentTopic
```

This comprehensive incident response framework ensures rapid detection, containment, and recovery from container security incidents while maintaining detailed documentation and continuous improvement processes.