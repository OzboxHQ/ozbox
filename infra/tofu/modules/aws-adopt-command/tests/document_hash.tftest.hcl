# What Systems Manager reports as the document's hash is compared with the SHA-256 of the file the program pins, on the apply
# that makes the document (the API reference does not say what it hashes, or that a mismatch is refused, so this is where a wrong
# assumption stops, with a reason, instead of every command being refused later). invariants.tftest.hcl's mock reports the right
# hash; this file's reports a wrong one, and the module must refuse it.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }

  mock_resource "aws_ssm_document" {
    defaults = {
      hash = "0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
}

variables {
  name       = "fleet-a"
  account_id = "123456789012"
}

run "a_document_the_system_hashed_differently_is_refused" {
  command = plan

  expect_failures = [aws_ssm_document.adopt]
}
