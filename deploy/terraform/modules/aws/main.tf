terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  required_version = ">= 1.10"
}

provider "aws" {
  region = var.region
}

# ── AMI: latest Ubuntu 22.04 LTS amd64 ───────────────────────────────────────

data "aws_ami" "ubuntu_2204" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# ── SSH key pair ──────────────────────────────────────────────────────────────

resource "aws_key_pair" "this" {
  key_name   = "${var.name_prefix}-${var.domain}-key"
  public_key = var.ssh_public_key

  tags = {
    Name    = "${var.name_prefix}-${var.domain}-key"
    project = var.name_prefix
    domain  = var.domain
  }
}

# ── Security group ────────────────────────────────────────────────────────────
# Rules:
#   - TCP 80/443 inbound from anywhere (public C2 traffic)
#   - TCP 22 inbound from operator_ip ONLY (no public SSH)
#   - All egress (Docker pulls, apt updates, C2 team server comms)

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-${var.domain}-sg"
  description = "InfraGuard redirector - web open, SSH restricted to operator"

  # HTTP inbound
  ingress {
    description = "HTTP inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS inbound
  ingress {
    description = "HTTPS inbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH restricted to operator IP - NEVER 0.0.0.0/0
  ingress {
    description = "SSH from operator only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
  }

  # Unrestricted egress (Docker pulls, apt, upstream C2 comms)
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.name_prefix}-${var.domain}-sg"
    project = var.name_prefix
    domain  = var.domain
  }
}

# ── EC2 instance ──────────────────────────────────────────────────────────────
# user_data installs Docker and starts the container.
# IMPORTANT (Pitfall 4): Do NOT embed API tokens or SSH keys in user_data -
# they are visible in the AWS console to any IAM user with ec2:DescribeInstances.
# Secrets are passed to the container via SSH post-provisioning or AWS Secrets Manager.

resource "aws_instance" "this" {
  ami                    = data.aws_ami.ubuntu_2204.id
  instance_type          = var.instance_size
  key_name               = aws_key_pair.this.key_name
  vpc_security_group_ids = [aws_security_group.this.id]

  user_data = <<-CLOUD_INIT
    #!/bin/bash
    set -euo pipefail

    # ── Update packages ──────────────────────────────────────────────────────
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get upgrade -y -qq

    # ── Install Docker via official repo (not snap) ──────────────────────────
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
      https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # ── Enable and start Docker ──────────────────────────────────────────────
    systemctl enable docker
    systemctl start docker

    # ── Pull or build the InfraGuard image ──────────────────────────────────
    # If docker_image looks like a registry image (contains '/'), pull it.
    # Otherwise build from a git clone of the project.
    DOCKER_IMAGE="${var.docker_image}"
    if echo "$DOCKER_IMAGE" | grep -q '/'; then
      docker pull "$DOCKER_IMAGE"
    else
      apt-get install -y -qq git
      git clone https://github.com/Lavender-exe/InfraGuard.git /opt/infraguard
      docker build -t "$DOCKER_IMAGE" /opt/infraguard
    fi

    # ── Signal provisioning complete ─────────────────────────────────────────
    touch /var/lib/infraguard-bootstrap-done
  CLOUD_INIT

  tags = {
    Name    = "${var.name_prefix}-${var.domain}"
    project = var.name_prefix
    domain  = var.domain
  }
}
