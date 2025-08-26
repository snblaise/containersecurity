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

variable "config_delivery_frequency" {
  description = "Frequency of Config snapshots"
  type        = string
  default     = "TwentyFour_Hours"
  validation {
    condition = contains([
      "One_Hour",
      "Three_Hours", 
      "Six_Hours",
      "Twelve_Hours",
      "TwentyFour_Hours"
    ], var.config_delivery_frequency)
    error_message = "Config delivery frequency must be a valid option."
  }
}

variable "enable_remediation" {
  description = "Enable automatic remediation for Config rules"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Email address for compliance notifications"
  type        = string
  default     = ""
}

variable "required_log_types" {
  description = "Required EKS log types"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}