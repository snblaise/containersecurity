# Route 53 Resolver DNS Firewall for Domain-based Access Control
# This configuration implements DNS filtering to control domain access from containers

# DNS Firewall Rule Group for Container Security
resource "aws_route53_resolver_firewall_rule_group" "container_dns_filtering" {
  name = "${var.cluster_name}-container-dns-filtering"

  tags = {
    Name        = "${var.cluster_name}-container-dns-filtering"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# Allow AWS service domains
resource "aws_route53_resolver_firewall_rule" "allow_aws_services" {
  name                    = "allow-aws-services"
  action                  = "ALLOW"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.aws_services.id
  priority                = 100
}

# Allow container registries
resource "aws_route53_resolver_firewall_rule" "allow_container_registries" {
  name                    = "allow-container-registries"
  action                  = "ALLOW"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.container_registries.id
  priority                = 200
}

# Allow package repositories
resource "aws_route53_resolver_firewall_rule" "allow_package_repos" {
  name                    = "allow-package-repos"
  action                  = "ALLOW"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.package_repositories.id
  priority                = 300
}

# Block malicious domains
resource "aws_route53_resolver_firewall_rule" "block_malicious" {
  name                    = "block-malicious-domains"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.malicious_domains.id
  priority                = 400
}

# Default block rule for unlisted domains
resource "aws_route53_resolver_firewall_rule" "default_block" {
  name                    = "default-block-unlisted"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.catch_all.id
  priority                = 1000
}

# Domain Lists
resource "aws_route53_resolver_firewall_domain_list" "aws_services" {
  name = "${var.cluster_name}-aws-services"
  domains = [
    "amazonaws.com",
    "aws.amazon.com",
    "amazontrust.com",
    "awsstatic.com",
    "cloudfront.net"
  ]

  tags = {
    Name        = "${var.cluster_name}-aws-services"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

resource "aws_route53_resolver_firewall_domain_list" "container_registries" {
  name = "${var.cluster_name}-container-registries"
  domains = [
    "docker.io",
    "registry-1.docker.io",
    "auth.docker.io",
    "production.cloudflare.docker.com",
    "gcr.io",
    "k8s.gcr.io",
    "registry.k8s.io",
    "quay.io"
  ]

  tags = {
    Name        = "${var.cluster_name}-container-registries"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

resource "aws_route53_resolver_firewall_domain_list" "package_repositories" {
  name = "${var.cluster_name}-package-repos"
  domains = [
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "packages.cloud.google.com",
    "download.docker.com",
    "apt.kubernetes.io",
    "packages.microsoft.com",
    "rpm.releases.hashicorp.com"
  ]

  tags = {
    Name        = "${var.cluster_name}-package-repos"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

resource "aws_route53_resolver_firewall_domain_list" "malicious_domains" {
  name = "${var.cluster_name}-malicious-domains"
  domains = [
    # Example malicious domains - should be populated from threat intelligence
    "malware-example.com",
    "phishing-example.net",
    "botnet-c2.org"
  ]

  tags = {
    Name        = "${var.cluster_name}-malicious-domains"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

resource "aws_route53_resolver_firewall_domain_list" "catch_all" {
  name = "${var.cluster_name}-catch-all"
  domains = [
    "*"
  ]

  tags = {
    Name        = "${var.cluster_name}-catch-all"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# Associate DNS Firewall with VPC
resource "aws_route53_resolver_firewall_rule_group_association" "container_dns_filtering" {
  name                   = "${var.cluster_name}-dns-filtering-association"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.container_dns_filtering.id
  vpc_id                 = var.vpc_id
  priority               = 100

  tags = {
    Name        = "${var.cluster_name}-dns-filtering-association"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# CloudWatch Log Group for DNS Firewall
resource "aws_cloudwatch_log_group" "dns_firewall_logs" {
  name              = "/aws/route53resolver/${var.cluster_name}-dns-firewall"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.cluster_name}-dns-firewall-logs"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# DNS Firewall Config for logging
resource "aws_route53_resolver_firewall_config" "container_dns_logging" {
  resource_id                = var.vpc_id
  firewall_fail_open         = "DISABLED"
  
  tags = {
    Name        = "${var.cluster_name}-dns-firewall-config"
    Environment = var.environment
    Purpose     = "container-security"
  }
}