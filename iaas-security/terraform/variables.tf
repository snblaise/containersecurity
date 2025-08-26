# Variables for IaaS Security Configuration

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "secure-cluster"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.cluster_name))
    error_message = "Cluster name must start with a letter and contain only alphanumeric characters and hyphens."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

# VPC Configuration Variables
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "At least 2 public subnets are required for high availability."
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24", "10.0.30.0/24"]

  validation {
    condition     = length(var.private_subnet_cidrs) >= 2
    error_message = "At least 2 private subnets are required for high availability."
  }
}

# EKS Configuration Variables
variable "kubernetes_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"

  validation {
    condition     = can(regex("^1\\.(2[4-9]|[3-9][0-9])$", var.kubernetes_version))
    error_message = "Kubernetes version must be 1.24 or higher."
  }
}

variable "node_instance_types" {
  description = "EC2 instance types for EKS worker nodes"
  type        = list(string)
  default     = ["m5.large", "m5.xlarge"]

  validation {
    condition     = length(var.node_instance_types) > 0
    error_message = "At least one instance type must be specified."
  }
}

variable "node_desired_capacity" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 3

  validation {
    condition     = var.node_desired_capacity >= 2
    error_message = "Desired capacity must be at least 2 for high availability."
  }
}

variable "node_max_capacity" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 10

  validation {
    condition     = var.node_max_capacity >= var.node_desired_capacity
    error_message = "Maximum capacity must be greater than or equal to desired capacity."
  }
}

variable "node_min_capacity" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 2

  validation {
    condition     = var.node_min_capacity >= 1
    error_message = "Minimum capacity must be at least 1."
  }
}

# Security Configuration Variables
variable "enable_cluster_encryption" {
  description = "Enable EKS cluster encryption for secrets"
  type        = bool
  default     = true
}

variable "enable_private_endpoint" {
  description = "Enable private API server endpoint"
  type        = bool
  default     = true
}

variable "enable_public_endpoint" {
  description = "Enable public API server endpoint"
  type        = bool
  default     = false
}

variable "public_access_cidrs" {
  description = "CIDR blocks that can access the public API server endpoint"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.public_access_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All public access CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "enable_irsa" {
  description = "Enable IAM Roles for Service Accounts (IRSA)"
  type        = bool
  default     = true
}

variable "enable_pod_security_policy" {
  description = "Enable Pod Security Policy (deprecated, use Pod Security Standards)"
  type        = bool
  default     = false
}

variable "enable_network_policy" {
  description = "Enable Kubernetes Network Policy support"
  type        = bool
  default     = true
}

# Monitoring and Logging Variables
variable "enable_cluster_logging" {
  description = "Enable EKS cluster logging"
  type        = bool
  default     = true
}

variable "cluster_log_types" {
  description = "List of EKS cluster log types to enable"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  validation {
    condition = alltrue([
      for log_type in var.cluster_log_types : contains([
        "api", "audit", "authenticator", "controllerManager", "scheduler"
      ], log_type)
    ])
    error_message = "Invalid log type. Valid types are: api, audit, authenticator, controllerManager, scheduler."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "enable_container_insights" {
  description = "Enable CloudWatch Container Insights"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable GuardDuty for EKS protection"
  type        = bool
  default     = true
}

# Encryption Variables
variable "kms_key_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 7

  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "KMS key deletion window must be between 7 and 30 days."
  }
}

variable "enable_kms_key_rotation" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

variable "enable_ebs_encryption" {
  description = "Enable EBS encryption by default"
  type        = bool
  default     = true
}

# Node Hardening Variables
variable "enable_node_hardening" {
  description = "Enable automated node hardening via SSM"
  type        = bool
  default     = true
}

variable "node_hardening_schedule" {
  description = "Cron expression for node hardening schedule"
  type        = string
  default     = "cron(0 2 * * ? *)" # Daily at 2 AM UTC

  validation {
    condition     = can(regex("^cron\\(", var.node_hardening_schedule))
    error_message = "Node hardening schedule must be a valid cron expression."
  }
}

variable "enable_automated_patching" {
  description = "Enable automated node patching"
  type        = bool
  default     = true
}

variable "patching_schedule" {
  description = "Cron expression for automated patching schedule"
  type        = string
  default     = "cron(0 3 ? * SUN *)" # Weekly on Sunday at 3 AM UTC

  validation {
    condition     = can(regex("^cron\\(", var.patching_schedule))
    error_message = "Patching schedule must be a valid cron expression."
  }
}

variable "patch_reboot_option" {
  description = "Reboot option for patching (RebootIfNeeded, NoReboot)"
  type        = string
  default     = "RebootIfNeeded"

  validation {
    condition     = contains(["RebootIfNeeded", "NoReboot"], var.patch_reboot_option)
    error_message = "Patch reboot option must be either 'RebootIfNeeded' or 'NoReboot'."
  }
}

# Network Security Variables
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "VPC Flow Logs retention in days"
  type        = number
  default     = 30
}

variable "enable_network_firewall" {
  description = "Enable AWS Network Firewall for egress filtering"
  type        = bool
  default     = false
}

variable "allowed_egress_domains" {
  description = "List of allowed egress domains for Network Firewall"
  type        = list(string)
  default = [
    "*.amazonaws.com",
    "*.docker.io",
    "*.docker.com",
    "quay.io",
    "gcr.io",
    "k8s.gcr.io",
    "registry.k8s.io"
  ]
}

# Compliance and Governance Variables
variable "enable_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true
}

variable "config_delivery_frequency" {
  description = "AWS Config delivery frequency"
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition = contains([
      "One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"
    ], var.config_delivery_frequency)
    error_message = "Invalid Config delivery frequency."
  }
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for API logging"
  type        = bool
  default     = true
}

variable "cloudtrail_retention_days" {
  description = "CloudTrail log retention in days"
  type        = number
  default     = 90
}

# Tags
variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "cost_center" {
  description = "Cost center for resource tagging"
  type        = string
  default     = ""
}

variable "project" {
  description = "Project name for resource tagging"
  type        = string
  default     = ""
}

variable "owner" {
  description = "Owner for resource tagging"
  type        = string
  default     = ""
}