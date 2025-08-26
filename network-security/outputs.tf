# Outputs for Network Security Configuration

# Network Firewall Outputs
output "network_firewall_arn" {
  description = "ARN of the Network Firewall"
  value       = aws_networkfirewall_firewall.container_security_firewall.arn
}

output "network_firewall_id" {
  description = "ID of the Network Firewall"
  value       = aws_networkfirewall_firewall.container_security_firewall.id
}

output "firewall_policy_arn" {
  description = "ARN of the Network Firewall Policy"
  value       = aws_networkfirewall_firewall_policy.container_security_policy.arn
}

# VPC Endpoints Outputs
output "vpc_endpoint_ecr_api_id" {
  description = "ID of the ECR API VPC endpoint"
  value       = aws_vpc_endpoint.ecr_api.id
}

output "vpc_endpoint_ecr_dkr_id" {
  description = "ID of the ECR DKR VPC endpoint"
  value       = aws_vpc_endpoint.ecr_dkr.id
}

output "vpc_endpoint_s3_id" {
  description = "ID of the S3 VPC endpoint"
  value       = aws_vpc_endpoint.s3.id
}

output "vpc_endpoint_security_group_id" {
  description = "Security Group ID for VPC endpoints"
  value       = aws_security_group.vpc_endpoints.id
}

# DNS Filtering Outputs
output "dns_firewall_rule_group_id" {
  description = "ID of the DNS Firewall Rule Group"
  value       = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
}

output "dns_firewall_rule_group_arn" {
  description = "ARN of the DNS Firewall Rule Group"
  value       = aws_route53_resolver_firewall_rule_group.container_dns_filtering.arn
}

# CloudWatch Log Groups
output "network_firewall_log_group_name" {
  description = "Name of the Network Firewall CloudWatch log group"
  value       = aws_cloudwatch_log_group.network_firewall_logs.name
}

output "dns_firewall_log_group_name" {
  description = "Name of the DNS Firewall CloudWatch log group"
  value       = aws_cloudwatch_log_group.dns_firewall_logs.name
}

# VPC and Subnet Outputs
output "private_subnet_ids" {
  description = "IDs of the private EKS node subnets"
  value       = aws_subnet.private_eks_nodes[*].id
}

output "private_subnet_cidrs_output" {
  description = "CIDR blocks of the private EKS node subnets"
  value       = aws_subnet.private_eks_nodes[*].cidr_block
}

output "firewall_subnet_ids" {
  description = "IDs of the firewall subnets"
  value       = var.enable_network_firewall ? aws_subnet.firewall_subnets[*].id : []
}

output "data_subnet_ids" {
  description = "IDs of the data subnets"
  value       = var.create_data_subnets ? aws_subnet.private_data[*].id : []
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (for NAT Gateway)"
  value       = var.enable_nat_gateway ? aws_subnet.public_nat[*].id : []
}

output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways"
  value       = var.enable_nat_gateway ? aws_nat_gateway.private_eks_nodes[*].id : []
}

output "private_route_table_ids" {
  description = "IDs of the private route tables"
  value       = aws_route_table.private_eks_nodes[*].id
}

# Security Group Outputs
output "eks_control_plane_security_group_id" {
  description = "Security Group ID for EKS control plane"
  value       = aws_security_group.eks_control_plane.id
}

output "eks_worker_nodes_security_group_id" {
  description = "Security Group ID for EKS worker nodes"
  value       = aws_security_group.eks_worker_nodes.id
}

output "eks_pods_security_group_id" {
  description = "Security Group ID for EKS pods"
  value       = aws_security_group.eks_pods.id
}

output "load_balancer_security_group_id" {
  description = "Security Group ID for load balancer"
  value       = aws_security_group.load_balancer.id
}

output "bastion_security_group_id" {
  description = "Security Group ID for bastion host"
  value       = var.enable_ssh_access ? aws_security_group.bastion[0].id : null
}

output "database_security_group_id" {
  description = "Security Group ID for database"
  value       = var.create_data_subnets ? aws_security_group.database[0].id : null
}