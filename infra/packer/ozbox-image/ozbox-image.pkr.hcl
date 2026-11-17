# Oz Box machine image: Ubuntu 24.04 LTS plus the small base a box needs (web IDE, remote desktop, tunnel, box daemon).
# Everything else is a tool the person chooses later from the catalog (catalog/catalog.toml).
# Two sources (AWS AMI, Hetzner snapshot) share one provisioning script. Every downloaded artefact is pinned
# by version and verified by sha256 inside scripts/provision.sh.

packer {
  required_version = ">= 1.11.0"

  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "~> 1.3"
    }
    hcloud = {
      source  = "github.com/hetznercloud/hcloud"
      version = "~> 1.6"
    }
  }
}

variable "image_version" {
  type        = string
  default     = "0.1.0"
  description = "Oz Box image version, used in the image name and the ozbox-image-version tag."
}

variable "arch" {
  type        = string
  default     = "amd64"
  description = "amd64 or arm64. Selects the base image, the build machine and the pinned artefact checksums."

  validation {
    condition     = contains(["amd64", "arm64"], var.arch)
    error_message = "The arch must be amd64 or arm64."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_instance_type" {
  type        = string
  default     = ""
  description = "Build instance type. Empty picks t3.large (amd64) or t4g.large (arm64)."
}

variable "aws_subnet_id" {
  type        = string
  default     = ""
  description = "A subnet to build in (required for the AWS build). A private subnet (the default) needs a route out for the Session Manager endpoints; a public one needs aws_associate_public_ip. Either way no port is open: see aws_security_group_id."
}

variable "aws_associate_public_ip" {
  type        = bool
  default     = false
  description = "Give the build instance a public address. False (the default) suits a private subnet. Set true only when the subnet is public and is how the instance reaches the Session Manager endpoints; the security group still has NO inbound rule and Packer still reaches the instance through Session Manager, never SSH over the network."
}

variable "aws_encrypt_boot" {
  type        = bool
  default     = true
  description = "Encrypt the image's snapshot. An encrypted image can never be made public, so the public release build sets this false. A box made from the image always has an encrypted root volume (the aws-box module encrypts it at launch)."
}

variable "aws_security_group_id" {
  type        = string
  default     = ""
  description = "An existing, tagged security group with NO inbound rule (required for the AWS build). Packer then creates none, so no port opens, not even SSH."
}

variable "aws_instance_profile" {
  type        = string
  default     = ""
  description = "An existing instance profile that carries the SSM core policy. Empty: Packer creates a temporary one."
}

variable "aws_copy_regions" {
  type        = list(string)
  default     = []
  description = "Also copy the image to these regions (the build region is ignored if listed). Empty: no copy. The release manifest records the image id for the build region and for each of these."
}

variable "hcloud_location" {
  type    = string
  default = "fsn1"
}

variable "hcloud_server_type" {
  type        = string
  default     = ""
  description = "Build server type. Empty picks cpx31 (amd64) or cax31 (arm64)."
}

variable "hcloud_token" {
  type      = string
  default   = ""
  sensitive = true
}

variable "ozboxd_binary" {
  type        = string
  default     = ""
  description = "Path of the ozboxd binary built for this arch in the same workflow run. The build uploads it to the instance and provision.sh installs it at /usr/local/bin/ozboxd."
}

variable "build_sha256" {
  type        = string
  default     = ""
  description = "The build hash of this recipe (scripts/packer-build-hash.sh). One part of the disk generation provision.sh records (ADR 0038)."
}

variable "first_boot_sha256" {
  type        = string
  default     = ""
  description = "The first-boot hash of this commit (scripts/first-boot-hash.sh). One part of the disk generation provision.sh records (ADR 0038)."
}

variable "ozboxd_sha256" {
  type        = string
  default     = ""
  description = "SHA-256 of that binary. provision.sh refuses a file that does not match, and records it in /etc/ozbox/image-release."
}

variable "ozbox_binary" {
  type        = string
  default     = ""
  description = "Path of the ozbox program built for this arch in the same workflow run. The build uploads it to the instance and provision.sh installs it at /usr/local/bin/ozbox (root-owned), where the secrets units run it."
}

variable "ozbox_sha256" {
  type        = string
  default     = ""
  description = "SHA-256 of that program. provision.sh refuses a file that does not match, and records it in /etc/ozbox/image-release."
}

variable "source_commit" {
  type        = string
  default     = ""
  description = "The commit the image and its ozboxd were built from."
}

# Pinned artefacts. Versions and checksums live here, one place, reviewed together.
variable "code_server_version" {
  type    = string
  default = "4.145.2"
}

variable "kasmvnc_version" {
  type    = string
  default = "1.5.2"
}

variable "cloudflared_version" {
  type    = string
  default = "2026.10.7"
}

locals {
  timestamp  = formatdate("YYYYMMDDhhmmss", timestamp())
  image_name = "ozbox-${var.image_version}-${local.timestamp}"

  # Everything the build creates carries these, so a build role can be limited to Oz Box's own resources.
  tags = {
    "ozbox-managed"       = "true"
    "ozbox-image"         = var.image_version
    "ozbox-image-version" = var.image_version
  }

  # sha256 of each artefact per architecture, from the sha256 digest GitHub records for each release asset.
  sha256 = {
    amd64 = {
      code_server = "7eddbdeaab34380bde3ac3bbadce58fe2f5722c4877f331ea593ae797c2517e1"
      kasmvnc     = "89a5d1fbe9e032b122202be158a2b25f15c97e0a5b8dcf92a5e6835c7b7b2acd"
      cloudflared = "70b1a1e0f46033ffc8d90b406e554044ba6cbf2e4360295ef1163aed31e09393"
    }
    arm64 = {
      code_server = "0fa9af7f602536b1e320a17d32bb1a85e4a924fdc09283898f1bea73d2a5c1e7"
      kasmvnc     = "4d680f3d1eb77fb155ae67af7f9fa25d7fbd38a7f69ae146784c7f738e2eed1a"
      cloudflared = "d9407eb6e70ac31f54978a6b408a0320b51b664a6d0b498248692d7ac56bf836"
    }
  }

  checksums = local.sha256[var.arch]

  provision_env = [
    "OZBOX_ARCH=${var.arch}",
    "OZBOX_IMAGE_VERSION=${var.image_version}",
    "CODE_SERVER_VERSION=${var.code_server_version}",
    "CODE_SERVER_SHA256=${local.checksums.code_server}",
    "KASMVNC_VERSION=${var.kasmvnc_version}",
    "KASMVNC_SHA256=${local.checksums.kasmvnc}",
    "CLOUDFLARED_VERSION=${var.cloudflared_version}",
    "CLOUDFLARED_SHA256=${local.checksums.cloudflared}",
    "OZBOXD_SHA256=${var.ozboxd_sha256}",
    "OZBOX_CLI_SHA256=${var.ozbox_sha256}",
    "OZBOX_SOURCE_COMMIT=${var.source_commit}",
    "OZBOX_FIRST_BOOT_SHA256=${var.first_boot_sha256}",
    "OZBOX_BUILD_SHA256=${var.build_sha256}",
  ]
}

source "amazon-ebs" "ozbox" {
  region        = var.aws_region
  instance_type = var.aws_instance_type != "" ? var.aws_instance_type : (var.arch == "arm64" ? "t4g.large" : "t3.large")
  ami_name      = local.image_name
  ami_regions   = [for r in var.aws_copy_regions : r if r != var.aws_region]

  # No inbound port, even while building: Packer reaches the instance through AWS Systems Manager Session Manager,
  # with an existing security group that has no inbound rule (so Packer creates none). The subnet is private, or public with
  # a public address for the outbound path to the Session Manager endpoints (aws_associate_public_ip): nothing connects IN
  # either way. (The Hetzner source below has no such service, so it still uses SSH.)
  communicator                = "ssh"
  ssh_interface               = "session_manager"
  ssh_username                = "ubuntu"
  # Packer's own temporary key is removed from the image (a public image must carry no key, not even one that is dead).
  ssh_clear_authorized_keys   = true
  associate_public_ip_address = var.aws_associate_public_ip
  subnet_id                   = var.aws_subnet_id
  security_group_id           = var.aws_security_group_id
  iam_instance_profile        = var.aws_instance_profile != "" ? var.aws_instance_profile : null

  # With no existing profile, Packer makes a temporary one. Its policy document needs a Statement block (a bare
  # Effect/Action/Resource does not parse). Least privilege: only what Session Manager needs (the intent of
  # AmazonSSMManagedInstanceCore's Session Manager part) and the one S3 read the SSM agent makes; no other service.
  dynamic "temporary_iam_instance_profile_policy_document" {
    for_each = var.aws_instance_profile == "" ? [1] : []
    content {
      Version = "2012-10-17"
      Statement {
        Effect   = "Allow"
        Action   = ["ssm:UpdateInstanceInformation", "ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel", "s3:GetEncryptionConfiguration"]
        Resource = ["*"]
      }
    }
  }

  # Canonical's public publisher id; this is the official Ubuntu 24.04 LTS image.
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-${var.arch}-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  imds_support = "v2.0"

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 16
    volume_type           = "gp3"
    delete_on_termination = true
  }

  encrypt_boot = var.aws_encrypt_boot

  # Tag at creation: instance, volumes, snapshot, image.
  run_tags          = merge(local.tags, { Name = "${local.image_name}-build" })
  run_volume_tags   = local.tags
  tags              = merge(local.tags, { Name = local.image_name })
  snapshot_tags     = local.tags
}

source "hcloud" "ozbox" {
  token         = var.hcloud_token
  location      = var.hcloud_location
  server_type   = var.hcloud_server_type != "" ? var.hcloud_server_type : (var.arch == "arm64" ? "cax31" : "cpx31")
  image         = "ubuntu-24.04"
  ssh_username  = "root"
  snapshot_name = local.image_name
  snapshot_labels = local.tags
}

build {
  name = "ozbox"

  sources = [
    "source.amazon-ebs.ozbox",
    "source.hcloud.ozbox",
  ]

  # The box daemon built in this workflow run. The image and its agent are one release.
  provisioner "file" {
    source      = var.ozboxd_binary
    destination = "/tmp/ozboxd-upload"
  }

  # The ozbox program built in the same run (root-owned on the image, so the box user cannot replace what the secrets
  # service runs).
  provisioner "file" {
    source      = var.ozbox_binary
    destination = "/tmp/ozbox-upload"
  }

  # The script that computes the disk generation (ADR 0038); provision.sh runs it and removes it.
  provisioner "file" {
    source      = "${path.root}/scripts/disk-generation.sh"
    destination = "/tmp/ozbox-disk-generation.sh"
  }

  provisioner "shell" {
    script           = "${path.root}/scripts/provision.sh"
    environment_vars = local.provision_env
    execute_command  = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E bash {{ .Path }}"
  }

  # What went in, for the release manifest and its software bill of materials. Downloaded over the same Session
  # Manager connection; nothing is uploaded to the instance.
  provisioner "file" {
    only        = ["amazon-ebs.ozbox"]
    direction   = "download"
    source      = "/etc/ozbox/packages.txt"
    destination = "${path.cwd}/packages-${var.arch}.txt"
  }

  # The disk generation and its parts, for the release manifest's `upgrade` record.
  provisioner "file" {
    only        = ["amazon-ebs.ozbox"]
    direction   = "download"
    source      = "/etc/ozbox/disk-parts"
    destination = "${path.cwd}/disk-parts-${var.arch}.txt"
  }

  provisioner "file" {
    only        = ["amazon-ebs.ozbox"]
    direction   = "download"
    source      = "/etc/ozbox/dpkg-status"
    destination = "${path.cwd}/dpkg-status-${var.arch}"
  }

  # Last, after every download over the same session: arrange for the build instance's own state (the SSM agent's
  # registration and logs, Packer's temporary key) to be cleared when it STOPS, after the agent has stopped and before the
  # snapshot. Done by a transient unit in /run, so nothing of it is in the image. See scripts/image-wipe-install.sh.
  provisioner "file" {
    only        = ["amazon-ebs.ozbox"]
    source      = "${path.root}/scripts/image-wipe.sh"
    destination = "/tmp/ozbox-image-wipe.sh"
  }

  provisioner "shell" {
    only            = ["amazon-ebs.ozbox"]
    script          = "${path.root}/scripts/image-wipe-install.sh"
    execute_command = "chmod +x {{ .Path }}; sudo -E bash {{ .Path }}"
  }

  post-processor "manifest" {
    output     = "${path.cwd}/packer-manifest-${var.arch}.json"
    strip_path = true
  }
}
