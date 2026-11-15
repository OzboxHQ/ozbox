output "vpc_id" {
  description = "The VPC id."
  value       = aws_vpc.this.id
}

output "private_subnet_id" {
  description = "The private subnet for boxes: pass it as the box module's subnet_id (and `subnet_id` under [aws] in the CLI config)."
  value       = aws_subnet.private.id
}

output "public_subnet_id" {
  description = "The public subnet that holds only the NAT gateway."
  value       = aws_subnet.public.id
}

output "nat_gateway_id" {
  description = "The NAT gateway id."
  value       = aws_nat_gateway.this.id
}

output "availability_zone" {
  description = "The availability zone of both subnets."
  value       = local.az
}
