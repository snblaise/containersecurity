# Variables for Security Groups for Pods Terraform configuration

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  validation {
    condition     = length(var.cluster_name) > 0
    error_message = "Cluster name must not be empty."
  }
}

variable "vpc_name" {
  description = "Name of the VPC where EKS cluster is deployed"
  type        = string
  validation {
    condition     = length(var.vpc_name) > 0
    error_message = "VPC name must not be empty."
  }
}

variable "environment" {
  description = "Environment name (e.g., production, staging, development)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development."
  }
}

variable "enable_pci_compliance" {
  description = "Enable PCI DSS compliant security groups for payment processing"
  type        = bool
  default     = true
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the cluster"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "payment_processor_ips" {
  description = "IP addresses of external payment processors"
  type        = list(string)
  default = [
    "54.187.174.169/32",  # Stripe
    "54.187.205.235/32",  # Stripe
    "173.252.64.0/18",    # PayPal
    "64.4.240.0/19"       # PayPal
  ]
}

variable "monitoring_cidrs" {
  description = "CIDR blocks for monitoring and observability tools"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}