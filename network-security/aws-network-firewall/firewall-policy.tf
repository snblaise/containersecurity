# Network Firewall Policy Configuration
resource "aws_networkfirewall_firewall_policy" "container_security_policy" {
  name = "${var.cluster_name}-container-security-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.container_egress_rules.arn
      priority     = 100
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.domain_filtering_rules.arn
      priority     = 200
    }

    # AWS managed rule groups for additional protection
    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${data.aws_region.current.name}:aws:managed/stateful-rulegroup/MalwareDomainsStrictOrder"
      priority     = 300
    }

    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${data.aws_region.current.name}:aws:managed/stateful-rulegroup/BotNetCommandAndControlDomainsStrictOrder"
      priority     = 400
    }

    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }
  }

  tags = {
    Name        = "${var.cluster_name}-container-security-policy"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# Network Firewall
resource "aws_networkfirewall_firewall" "container_security_firewall" {
  name                = "${var.cluster_name}-container-security-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.container_security_policy.arn
  vpc_id              = var.vpc_id

  dynamic "subnet_mapping" {
    for_each = var.firewall_subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }

  tags = {
    Name        = "${var.cluster_name}-container-security-firewall"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# CloudWatch Log Group for Network Firewall
resource "aws_cloudwatch_log_group" "network_firewall_logs" {
  name              = "/aws/networkfirewall/${var.cluster_name}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.cluster_name}-network-firewall-logs"
    Environment = var.environment
    Purpose     = "container-security"
  }
}

# Network Firewall Logging Configuration
resource "aws_networkfirewall_logging_configuration" "container_security_logging" {
  firewall_arn = aws_networkfirewall_firewall.container_security_firewall.arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall_logs.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }

    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall_logs.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
  }
}

data "aws_region" "current" {}