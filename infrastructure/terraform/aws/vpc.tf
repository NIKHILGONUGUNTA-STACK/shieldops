# Multi-AZ VPC Architecture for Aegis SaaS Platform
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "aegis" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "aegis-${var.environment}-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.aegis.id

  tags = {
    Name = "aegis-${var.environment}-igw"
  }
}

# Public Subnets (ALB Ingress)
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.aegis.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                           = "aegis-${var.environment}-public-${count.index + 1}"
    "kubernetes.io/role/elb"                      = "1"
    "kubernetes.io/cluster/${var.cluster_name}"   = "shared"
  }
}

# Private Subnets (EKS Compute Nodes)
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.aegis.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 4)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name                                           = "aegis-${var.environment}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb"             = "1"
    "kubernetes.io/cluster/${var.cluster_name}"   = "shared"
  }
}

# Database Isolated Subnets (RDS & Redis)
resource "aws_subnet" "database" {
  count             = 3
  vpc_id            = aws_vpc.aegis.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 8)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "aegis-${var.environment}-db-${count.index + 1}"
  }
}

# NAT Gateway for Outbound EKS Traffic
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "aegis-${var.environment}-nat-eip"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "aegis-${var.environment}-nat"
  }
  depends_on = [aws_internet_gateway.gw]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.aegis.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "aegis-${var.environment}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.aegis.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "aegis-${var.environment}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
