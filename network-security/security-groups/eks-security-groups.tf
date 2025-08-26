# Security Groups for EKS Node and Pod Communication
# This configuration creates security groups with least-privilege access

# Security Group for EKS Control Plane
resource "aws_security_group" "eks_control_plane" {
  name_prefix = "${var.cluster_name}-control-plane-"
  vpc_id      = var.vpc_id
  description = "Security group for EKS control plane"

  # Allow HTTPS from worker nodes
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_worker_nodes.id]
    description     = "HTTPS from worker nodes"
  }

  # Allow all outbound traffic to worker nodes
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.eks_worker_nodes.id]
    description     = "All traffic to worker nodes"
  }

  # Allow outbound HTTPS for VPC endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
    description = "HTTPS to VPC endpoints"
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-control-plane-sg"
      Environment = var.environment
      Purpose     = "eks-control-plane"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for EKS Worker Nodes
resource "aws_security_group" "eks_worker_nodes" {
  name_prefix = "${var.cluster_name}-worker-nodes-"
  vpc_id      = var.vpc_id
  description = "Security group for EKS worker nodes"

  # Allow inbound traffic from control plane
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.eks_control_plane.id]
    description     = "All traffic from control plane"
  }

  # Allow node-to-node communication
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
    description = "Node-to-node communication"
  }

  # Allow kubelet API from control plane
  ingress {
    from_port       = 10250
    to_port         = 10250
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_control_plane.id]
    description     = "Kubelet API from control plane"
  }

  # Allow NodePort services
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
    description = "NodePort services"
  }

  # Allow SSH access from bastion (if enabled)
  dynamic "ingress" {
    for_each = var.enable_ssh_access ? [1] : []
    content {
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = [aws_security_group.bastion[0].id]
      description     = "SSH from bastion host"
    }
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-worker-nodes-sg"
      Environment = var.environment
      Purpose     = "eks-worker-nodes"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Pod-to-Pod Communication
resource "aws_security_group" "eks_pods" {
  name_prefix = "${var.cluster_name}-pods-"
  vpc_id      = var.vpc_id
  description = "Security group for EKS pods"

  # Allow pod-to-pod communication within cluster
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
    description = "Pod-to-pod communication"
  }

  # Allow inbound traffic from ALB/NLB
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
    description     = "HTTP from load balancer"
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer.id]
    description     = "HTTPS from load balancer"
  }

  # Allow custom application ports
  dynamic "ingress" {
    for_each = var.custom_pod_ports
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
      description = ingress.value.description
    }
  }

  # Allow outbound traffic to AWS services via VPC endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.private_subnet_cidrs
    description = "HTTPS to VPC endpoints"
  }

  # Allow outbound DNS
  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS queries"
  }

  # Allow outbound HTTPS for external APIs (controlled by Network Firewall)
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to external services"
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-pods-sg"
      Environment = var.environment
      Purpose     = "eks-pods"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Load Balancer
resource "aws_security_group" "load_balancer" {
  name_prefix = "${var.cluster_name}-load-balancer-"
  vpc_id      = var.vpc_id
  description = "Security group for load balancer"

  # Allow inbound HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "HTTP from allowed networks"
  }

  # Allow inbound HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "HTTPS from allowed networks"
  }

  # Allow outbound to pods
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.eks_pods.id]
    description     = "All traffic to pods"
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-load-balancer-sg"
      Environment = var.environment
      Purpose     = "load-balancer"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Bastion Host (optional)
resource "aws_security_group" "bastion" {
  count = var.enable_ssh_access ? 1 : 0

  name_prefix = "${var.cluster_name}-bastion-"
  vpc_id      = var.vpc_id
  description = "Security group for bastion host"

  # Allow SSH from specific IP ranges
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidr_blocks
    description = "SSH from allowed networks"
  }

  # Allow outbound SSH to worker nodes
  egress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_worker_nodes.id]
    description     = "SSH to worker nodes"
  }

  # Allow outbound HTTPS for updates
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for updates"
  }

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-bastion-sg"
      Environment = var.environment
      Purpose     = "bastion-host"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for Database (if data subnets are created)
resource "aws_security_group" "database" {
  count = var.create_data_subnets ? 1 : 0

  name_prefix = "${var.cluster_name}-database-"
  vpc_id      = var.vpc_id
  description = "Security group for database"

  # Allow database access from pods
  ingress {
    from_port       = var.database_port
    to_port         = var.database_port
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_pods.id]
    description     = "Database access from pods"
  }

  # No outbound rules - databases should not initiate connections

  tags = merge(
    var.common_tags,
    {
      Name        = "${var.cluster_name}-database-sg"
      Environment = var.environment
      Purpose     = "database"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}