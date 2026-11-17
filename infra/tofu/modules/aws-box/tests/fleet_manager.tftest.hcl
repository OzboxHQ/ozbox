# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = {
      vpc_id            = "vpc-0123456789abcdef0"
      availability_zone = "us-east-1a"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  box_name     = "dev-1"
  machine_type = "m7i.4xlarge"
  work_disk_gb = 200
  image_id     = "ami-0123456789abcdef0"
  region       = "us-east-1"
  subnet_id    = "subnet-0123456789abcdef0"
  labels       = { team = "example" }
}

# ADR 0040 §8: the fleet roles are denied any change to what carries ozbox-fleet-manager, so main's machine and every disk
# of it carry the tag from the moment they exist, and nothing else ever does.
run "the_fleet_manager_is_marked_on_the_machine_and_every_disk" {
  command = apply

  variables {
    fleet_manager = true
  }

  assert {
    condition = alltrue([
      for t in [aws_instance.box.tags, aws_ebs_volume.work.tags, aws_instance.box.volume_tags] :
      t["ozbox-fleet-manager"] == "true"
    ])
    error_message = "main's machine, /work and system disk carry ozbox-fleet-manager"
  }
}

run "an_ordinary_box_is_not_the_fleet_manager" {
  command = apply

  assert {
    condition     = !contains(keys(aws_instance.box.tags), "ozbox-fleet-manager") && !contains(keys(aws_ebs_volume.work.tags), "ozbox-fleet-manager")
    error_message = "only fleet_manager = true marks a box"
  }
}

run "the_fleet_manager_mark_is_not_a_label" {
  command = plan

  variables {
    labels = { "ozbox-fleet-manager" = "true" }
  }

  expect_failures = [var.labels]
}
