# The isolated network an Oz Box lives in: one VPC, a private subnet for boxes, and a public subnet that holds
# only the NAT gateway through which boxes reach the internet (package mirrors, git, Session Manager).
#
# Invariants (asserted in tests/invariants.tftest.hcl):
#   - nothing in either subnet gets a public IP on launch; boxes live in the private subnet and are never reachable
#   - the private subnet's only way out is the NAT gateway; only the public subnet routes to the internet gateway
#   - no security group, network ACL or ingress rule of any kind is declared here
#   - every resource carries ozbox-managed=true (and the operator policy only touches tagged resources)
#
# Cost: a NAT gateway and its address bill by the hour while the network exists. Destroy the network when no box
# needs it.

locals {
  tags = merge(var.labels, {
    "ozbox-managed" = "true"
    "ozbox-network" = var.name
    "ozbox-region"  = var.region
  })

  az = coalesce(var.availability_zone, data.aws_availability_zones.available.names[0])
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "ozbox-${var.name}" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "ozbox-${var.name}" })
}

# Holds the NAT gateway only. No box is ever placed here.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = local.az
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "ozbox-${var.name}-public", "ozbox-role" = "nat" })
}

# Where boxes go. Pass its id as the box module's subnet_id.
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = local.az
  map_public_ip_on_launch = false
  tags                    = merge(local.tags, { Name = "ozbox-${var.name}-private", "ozbox-role" = "boxes" })
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = merge(local.tags, { Name = "ozbox-${var.name}-nat" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  tags          = merge(local.tags, { Name = "ozbox-${var.name}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "ozbox-${var.name}-public" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "ozbox-${var.name}-private" })
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}
