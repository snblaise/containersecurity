# Secrets Management with AWS Secrets Store CSI Driver

This directory contains configurations for secure secrets management in Amazon EKS using the AWS Secrets Store CSI Driver. The implementation provides envelope encryption with AWS KMS and runtime secrets injection without storing sensitive data in container images.

## Components

### SecretProviderClass Configurations
- `secret-provider-classes/` - YAML manifests for different secret types
- `kms-encryption/` - KMS key policies and encryption configurations
- `pod-examples/` - Pod specifications with secrets volume mounts
- `validation/` - Scripts to ensure secrets are not exposed in images

### Features
- AWS Secrets Manager integration with envelope encryption
- Runtime secrets mounting via CSI driver
- KMS-based encryption for secrets at rest
- Automatic secrets rotation support
- Pod-level secrets isolation

## Prerequisites
- Amazon EKS cluster with Secrets Store CSI Driver installed
- AWS Secrets Manager secrets created
- KMS keys configured for envelope encryption
- IRSA configured for pod-level AWS access

## Security Benefits
- Secrets never stored in container images
- Envelope encryption with customer-managed KMS keys
- Runtime-only secrets access
- Automatic rotation without pod restarts
- Audit trail through CloudTrail logging