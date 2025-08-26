# Route Table Configurations for Network Isolation
# This configuration creates isolated route tables for different subnet types

# Route table for private EKS node subnets
resource "aws_route_table" "private_eks_nodes" {
  count = var.private_subnet_count

  vpc_id = var.vpc_id

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-private-eks-nodes-rt-${count.index + 1}"
      Type        = "private"
      Environment = var.environment
      Purpose     = "eks-nodes"
    }
  )
}

# Route table associations for private EKS node subnets
resource "aws_route_table_association" "private_eks_nodes" {
  count = var.private_subnet_count

  subnet_id      = aws_subnet.private_eks_nodes[count.index].id
  route_table_id = aws_route_table.private_eks_nodes[count.index].id
}

# Route table for firewall subnets
resource "aws_route_table" "firewall_subnets" {
  count = var.enable_network_firewall ? var.private_subnet_count : 0

  vpc_id = var.vpc_id

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-firewall-rt-${count.index + 1}"
      Type        = "firewall"
      Environment = var.environment
      Purpose     = "network-firewall"
    }
  )
}

# Route table associations for firewall subnets
resource "aws_route_table_association" "firewall_subnets" {
  count = var.enable_network_firewall ? var.private_subnet_count : 0

  subnet_id      = aws_subnet.firewall_subnets[count.index].id
  route_table_id = aws_route_table.firewall_subnets[count.index].id
}

# Route table for data subnets (completely isolated)
resource "aws_route_table" "private_data" {
  count = var.create_data_subnets ? var.private_subnet_count : 0

  vpc_id = var.vpc_id

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-data-rt-${count.index + 1}"
      Type        = "data"
      Environment = var.environment
      Purpose     = "database-storage"
    }
  )
}

# Route table associations for data subnets
resource "aws_route_table_association" "private_data" {
  count = var.create_data_subnets ? var.private_subnet_count : 0

  subnet_id      = aws_subnet.private_data[count.index].id
  route_table_id = aws_route_table.private_data[count.index].id
}

# Routes for private EKS node subnets through NAT Gateway (if enabled)
resource "aws_route" "private_eks_nodes_nat" {
  count = var.enable_nat_gateway ? var.private_subnet_count : 0

  route_table_id         = aws_route_table.private_eks_nodes[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.nat_gateway_ids[count.index]
}

# Routes for private EKS node subnets through Network Firewall (if enabled)
resource "aws_route" "private_eks_nodes_firewall" {
  count = var.enable_network_firewall && !var.enable_nat_gateway ? var.private_subnet_count : 0

  route_table_id         = aws_route_table.private_eks_nodes[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = var.network_firewall_endpoint_ids[count.index]
}

# Routes for firewall subnets to NAT Gateway
resource "aws_route" "firewall_subnets_nat" {
  count = var.enable_network_firewall && var.enable_nat_gateway ? var.private_subnet_count : 0

  route_table_id         = aws_route_table.firewall_subnets[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.nat_gateway_ids[count.index]
}

# Routes for firewall subnets to Internet Gateway (if no NAT)
resource "aws_route" "firewall_subnets_igw" {
  count = var.enable_network_firewall && !var.enable_nat_gateway ? var.private_subnet_count : 0

  route_table_id         = aws_route_table.firewall_subnets[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = var.internet_gateway_id
}

# Local routes for VPC communication (automatically created by AWS)
# Additional routes for cross-AZ communication if needed
resource "aws_route" "cross_az_communication" {
  count = var.enable_cross_az_communication ? var.private_subnet_count : 0

  route_table_id         = aws_route_table.private_eks_nodes[count.index].id
  destination_cidr_block = var.vpc_cidr
  gateway_id             = "local"
}

# Route table for public subnets (if NAT gateways are used)
resource "aws_route_table" "public" {
  count = var.enable_nat_gateway ? 1 : 0

  vpc_id = var.vpc_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = var.internet_gateway_id
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-public-rt"
      Type        = "public"
      Environment = var.environment
      Purpose     = "nat-gateway"
    }
  )
}

# Public subnet for NAT Gateway (minimal, only for NAT)
resource "aws_subnet" "public_nat" {
  count = var.enable_nat_gateway ? var.private_subnet_count : 0

  vpc_id                  = var.vpc_id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-public-nat-subnet-${count.index + 1}"
      Type        = "public"
      Environment = var.environment
      Purpose     = "nat-gateway"
    }
  )
}

# Route table association for public NAT subnets
resource "aws_route_table_association" "public_nat" {
  count = var.enable_nat_gateway ? var.private_subnet_count : 0

  subnet_id      = aws_subnet.public_nat[count.index].id
  route_table_id = aws_route_table.public[0].id
}

# NAT Gateways for private subnet internet access
resource "aws_nat_gateway" "private_eks_nodes" {
  count = var.enable_nat_gateway ? var.private_subnet_count : 0

  allocation_id = aws_eip.nat_gateway[count.index].id
  subnet_id     = aws_subnet.public_nat[count.index].id

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-nat-gateway-${count.index + 1}"
      Environment = var.environment
      Purpose     = "private-subnet-internet-access"
    }
  )

  depends_on = [var.internet_gateway_id]
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat_gateway" {
  count = var.enable_nat_gateway ? var.private_subnet_count : 0

  domain = "vpc"

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-nat-gateway-eip-${count.index + 1}"
      Environment = var.environment
      Purpose     = "nat-gateway"
    }
  )

  depends_on = [var.internet_gateway_id]
}