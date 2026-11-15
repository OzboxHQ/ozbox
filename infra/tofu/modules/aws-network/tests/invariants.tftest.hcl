# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b"]
    }
  }
}

variables {
  name   = "test"
  region = "us-east-1"
  labels = { team = "example" }
}

run "boxes_live_in_a_private_subnet_with_no_public_ip" {
  command = apply

  assert {
    condition     = aws_subnet.private.map_public_ip_on_launch == false && aws_subnet.public.map_public_ip_on_launch == false
    error_message = "no subnet may hand out public IPs on launch"
  }

  assert {
    condition     = aws_subnet.private.cidr_block == "10.42.1.0/24" && aws_subnet.public.cidr_block == "10.42.0.0/24"
    error_message = "the two subnets are /24s carved from the /16"
  }

  assert {
    condition     = aws_subnet.private.availability_zone == "us-east-1a" && aws_subnet.public.availability_zone == "us-east-1a"
    error_message = "both subnets share the first available zone"
  }
}

run "the_private_subnet_leaves_only_through_the_nat_gateway" {
  command = apply

  assert {
    condition     = aws_route.private_nat.nat_gateway_id != null && aws_route.private_nat.gateway_id == null
    error_message = "the private route table must default to the NAT gateway, never the internet gateway"
  }

  assert {
    condition     = aws_route.public_internet.gateway_id != null && aws_route.public_internet.destination_cidr_block == "0.0.0.0/0"
    error_message = "only the public route table routes to the internet gateway"
  }

  assert {
    condition     = aws_nat_gateway.this.subnet_id == aws_subnet.public.id
    error_message = "the NAT gateway sits in the public subnet"
  }

  assert {
    condition     = aws_route_table_association.private.subnet_id == aws_subnet.private.id && aws_route_table_association.public.subnet_id == aws_subnet.public.id
    error_message = "each subnet uses its own route table"
  }
}

run "every_resource_is_tagged_and_reserved_tags_cannot_be_overridden" {
  command = apply

  variables {
    labels = { "ozbox-managed" = "false", team = "example" }
  }

  assert {
    condition = alltrue([
      aws_vpc.this.tags["ozbox-managed"] == "true",
      aws_internet_gateway.this.tags["ozbox-managed"] == "true",
      aws_subnet.public.tags["ozbox-managed"] == "true",
      aws_subnet.private.tags["ozbox-managed"] == "true",
      aws_eip.nat.tags["ozbox-managed"] == "true",
      aws_nat_gateway.this.tags["ozbox-managed"] == "true",
      aws_route_table.public.tags["ozbox-managed"] == "true",
      aws_route_table.private.tags["ozbox-managed"] == "true",
    ])
    error_message = "every taggable resource carries ozbox-managed=true, whatever the caller passes"
  }

  assert {
    condition     = aws_vpc.this.tags["ozbox-network"] == "test" && aws_vpc.this.tags["team"] == "example"
    error_message = "the network name and the caller's labels are kept"
  }
}

run "outputs_name_the_subnet_for_boxes" {
  command = apply

  assert {
    condition     = output.private_subnet_id == aws_subnet.private.id && output.public_subnet_id == aws_subnet.public.id
    error_message = "private_subnet_id is what a box is created in"
  }

  assert {
    condition     = output.availability_zone == "us-east-1a"
    error_message = "the zone is reported"
  }
}

run "an_explicit_zone_and_range_are_used" {
  command = apply

  variables {
    vpc_cidr          = "172.20.0.0/16"
    availability_zone = "us-east-1b"
  }

  assert {
    condition     = aws_subnet.private.cidr_block == "172.20.1.0/24" && aws_subnet.private.availability_zone == "us-east-1b"
    error_message = "the caller's range and zone win"
  }
}

run "name_rejects_uppercase" {
  command = plan

  variables {
    name = "Test"
  }

  expect_failures = [var.name]
}

run "range_must_be_a_private_slash_16" {
  command = plan

  variables {
    vpc_cidr = "8.8.0.0/16"
  }

  expect_failures = [var.vpc_cidr]
}

run "range_must_be_a_slash_16" {
  command = plan

  variables {
    vpc_cidr = "10.0.0.0/24"
  }

  expect_failures = [var.vpc_cidr]
}
