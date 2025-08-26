variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of KMS key for encryption"
  type        = string
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "container-security"
    ManagedBy   = "terraform"
  }
}

variable "enable_malware_protection" {
  description = "Enable GuardDuty malware protection"
  type        = bool
  default     = true
}

variable "enable_eks_runtime_monitoring" {
  description = "Enable GuardDuty EKS runtime monitoring"
  type        = bool
  default     = true
}

variable "finding_publishing_frequency" {
  description = "Frequency of publishing findings to CloudWatch Events"
  type        = string
  default     = "FIFTEEN_MINUTES"
  validation {
    condition = contains([
      "FIFTEEN_MINUTES",
      "ONE_HOUR",
      "SIX_HOURS"
    ], var.finding_publishing_frequency)
    error_message = "Finding publishing frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}