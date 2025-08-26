# Private Subnet Configurations for EKS Nodes
# This configuration creates secure private subnets for EKS worker nodes

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Private subnets for EKS worker nodes
resource "aws_subnet" "private_eks_nodes" {
  count = var.private_subnet_count

  vpc_id            = var.vpc_id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # Disable public IP assignment
  map_public_ip_on_launch = false

  tags = merge(
    var.common_tags,
    {
      Name                                        = "${var.cluster_name}-private-subnet-${count.index + 1}"
      Type                                        = "private"
      "kubernetes.io/role/internal-elb"          = "1"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
      Environment                                 = var.environment
      Purpose                                     = "eks-nodes"
    }
  )
}

# Private subnets for Network Firewall
resource "aws_subnet" "firewall_subnets" {
  count = var.enable_network_firewall ? var.private_subnet_count : 0

  vpc_id            = var.vpc_id
  cidr_block        = var.firewall_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # Disable public IP assignment
  map_public_ip_on_launch = false

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-firewall-subnet-${count.index + 1}"
      Type        = "firewall"
      Environment = var.environment
      Purpose     = "network-firewall"
    }
  )
}

# Private subnets for database/storage (if needed)
resource "aws_subnet" "private_data" {
  count = var.create_data_subnets ? var.private_subnet_count : 0

  vpc_id            = var.vpc_id
  cidr_block        = var.data_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # Disable public IP assignment
  map_public_ip_on_launch = false

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-data-subnet-${count.index + 1}"
      Type        = "data"
      Environment = var.environment
      Purpose     = "database-storage"
    }
  )
}

# Subnet group for RDS (if database subnets are created)
resource "aws_db_subnet_group" "private_data" {
  count = var.create_data_subnets ? 1 : 0

  name       = "${var.cluster_name}-private-data-subnet-group"
  subnet_ids = aws_subnet.private_data[*].id

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-private-data-subnet-group"
      Environment = var.environment
      Purpose     = "database"
    }
  )
}

# Network ACLs for private subnets
resource "aws_network_acl" "private_eks_nodes" {
  vpc_id     = var.vpc_id
  subnet_ids = aws_subnet.private_eks_nodes[*].id

  # Allow inbound HTTPS from VPC
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 443
    to_port    = 443
  }

  # Allow inbound HTTP from VPC
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 80
    to_port    = 80
  }

  # Allow inbound Kubernetes API
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 6443
    to_port    = 6443
  }

  # Allow inbound kubelet API
  ingress {
    protocol   = "tcp"
    rule_no    = 130
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 10250
    to_port    = 10250
  }

  # Allow inbound NodePort services
  ingress {
    protocol   = "tcp"
    rule_no    = 140
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 30000
    to_port    = 32767
  }

  # Allow inbound ephemeral ports for return traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 150
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow all outbound traffic
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-private-eks-nodes-nacl"
      Environment = var.environment
      Purpose     = "eks-nodes-security"
    }
  )
}

# Network ACL for firewall subnets
resource "aws_network_acl" "firewall_subnets" {
  count = var.enable_network_firewall ? 1 : 0

  vpc_id     = var.vpc_id
  subnet_ids = aws_subnet.firewall_subnets[*].id

  # Allow all inbound traffic for inspection
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow all outbound traffic
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-firewall-subnets-nacl"
      Environment = var.environment
      Purpose     = "network-firewall"
    }
  )
}