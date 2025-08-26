# Variables for Network Security Configuration

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., prod, staging, dev)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the EKS cluster is deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for VPC endpoints"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "List of private subnet CIDR blocks"
  type        = list(string)
}

variable "firewall_subnet_ids" {
  description = "List of subnet IDs for Network Firewall deployment"
  type        = list(string)
}

variable "private_route_table_ids" {
  description = "List of private route table IDs for S3 VPC endpoint"
  type        = list(string)
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 30
}

variable "enable_dns_filtering" {
  description = "Enable Route 53 Resolver DNS Firewall"
  type        = bool
  default     = true
}

variable "enable_network_firewall" {
  description = "Enable AWS Network Firewall"
  type        = bool
  default     = true
}

variable "allowed_domains" {
  description = "Additional domains to allow through DNS filtering"
  type        = list(string)
  default     = []
}

variable "blocked_domains" {
  description = "Additional domains to block through DNS filtering"
  type        = list(string)
  default     = []
}

# VPC and Subnet Configuration Variables
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "private_subnet_count" {
  description = "Number of private subnets to create"
  type        = number
  default     = 3
}

variable "firewall_subnet_cidrs" {
  description = "List of CIDR blocks for firewall subnets"
  type        = list(string)
  default     = []
}

variable "data_subnet_cidrs" {
  description = "List of CIDR blocks for data subnets"
  type        = list(string)
  default     = []
}

variable "public_subnet_cidrs" {
  description = "List of CIDR blocks for public subnets (NAT Gateway)"
  type        = list(string)
  default     = []
}

variable "create_data_subnets" {
  description = "Whether to create isolated data subnets"
  type        = bool
  default     = false
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnet internet access"
  type        = bool
  default     = true
}

variable "enable_cross_az_communication" {
  description = "Enable cross-AZ communication routes"
  type        = bool
  default     = true
}

variable "nat_gateway_ids" {
  description = "List of NAT Gateway IDs (if using existing NAT Gateways)"
  type        = list(string)
  default     = []
}

variable "network_firewall_endpoint_ids" {
  description = "List of Network Firewall endpoint IDs"
  type        = list(string)
  default     = []
}

variable "internet_gateway_id" {
  description = "Internet Gateway ID"
  type        = string
  default     = ""
}

# Security Group Configuration Variables
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access load balancer"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_ssh_access" {
  description = "Enable SSH access via bastion host"
  type        = bool
  default     = false
}

variable "ssh_allowed_cidr_blocks" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = []
}

variable "custom_pod_ports" {
  description = "Custom ports to allow for pod communication"
  type = list(object({
    port        = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  default = []
}

variable "database_port" {
  description = "Database port for security group rules"
  type        = number
  default     = 5432
}