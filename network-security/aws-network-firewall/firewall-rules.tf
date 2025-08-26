# AWS Network Firewall Configuration for Container Egress Control
# This configuration implements egress traffic filtering for EKS workloads

# Network Firewall Rule Group for Container Egress Control
resource "aws_networkfirewall_rule_group" "container_egress_rules" {
  capacity = 100
  name     = "${var.cluster_name}-container-egress-rules"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      stateful_rule {
        action = "PASS"
        header {
          destination      = "0.0.0.0/0"
          destination_port = "443"
          direction        = "FORWARD"
          protocol         = "TCP"
          source           = var.private_subnet_cidrs[0]
          source_port      = "ANY"
        }
        rule_option {
          keyword = "sid:1"
        }
      }

      stateful_rule {
        action = "PASS"
        header {
          destination      = "0.0.0.0/0"
          destination_port = "80"
          direction        = "FORWARD"
          protocol         = "TCP"
          source           = var.private_subnet_cidrs[0]
          source_port      = "ANY"
        }
        rule_option {
          keyword = "sid:2"
        }
      }

      # Allow DNS queries
      stateful_rule {
        action = "PASS"
        header {
          destination      = "0.0.0.0/0"
          destination_port = "53"
          direction        = "FORWARD"
          protocol         = "UDP"
          source           = var.private_subnet_cidrs[0]
          source_port      = "ANY"
        }
        rule_option {
          keyword = "sid:3"
        }
      }

      # Block all other egress traffic
      stateful_rule {
        action = "DROP"
        header {
          destination      = "0.0.0.0/0"
          destination_port = "ANY"
          direction        = "FORWARD"
          protocol         = "IP"
          source           = var.private_subnet_cidrs[0]
          source_port      = "ANY"
        }
        rule_option {
          keyword = "sid:100"
        }
      }
    }
  }

  tags = {
    Name        = "${var.cluster_name}-container-egress-rules"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# Domain-based filtering rule group
resource "aws_networkfirewall_rule_group" "domain_filtering_rules" {
  capacity = 200
  name     = "${var.cluster_name}-domain-filtering"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets = [
          # AWS service endpoints
          "*.amazonaws.com",
          "*.aws.amazon.com",
          
          # Container registries
          "*.dkr.ecr.*.amazonaws.com",
          "registry-1.docker.io",
          "auth.docker.io",
          "production.cloudflare.docker.com",
          
          # Package repositories
          "archive.ubuntu.com",
          "security.ubuntu.com",
          "packages.cloud.google.com",
          
          # Certificate authorities
          "ocsp.digicert.com",
          "crl3.digicert.com",
          "crl4.digicert.com",
          
          # Monitoring and logging
          "*.cloudwatch.*.amazonaws.com",
          "*.logs.*.amazonaws.com"
        ]
      }
    }
  }

  tags = {
    Name        = "${var.cluster_name}-domain-filtering"
    Environment = var.environment
    Purpose     = "container-security"
  }
}