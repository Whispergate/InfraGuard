terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.49"
    }
  }
  required_version = ">= 1.10"
}

# ── SSH key ──────────────────────────────────────────────────────────────

resource "hcloud_ssh_key" "this" {
  name       = "${var.name_prefix}-${var.domain}-key"
  public_key = var.ssh_public_key

  labels = {
    project = var.name_prefix
    domain  = replace(var.domain, ".", "-")
  }
}

# ── Firewall ─────────────────────────────────────────────────────────────
# Rules:
#   - TCP 80/443 inbound from anywhere (public traffic)
#   - TCP 22 inbound from operator_ip ONLY
#   - All outbound (Docker pulls, apt, upstream comms)

resource "hcloud_firewall" "this" {
  name = "${var.name_prefix}-${replace(var.domain, ".", "-")}-fw"

  labels = {
    project = var.name_prefix
    domain  = replace(var.domain, ".", "-")
  }

  rule {
    description = "HTTP inbound"
    direction   = "in"
    protocol    = "tcp"
    port        = "80"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "HTTPS inbound"
    direction   = "in"
    protocol    = "tcp"
    port        = "443"
    source_ips  = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "SSH from operator only"
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = [var.operator_ip]
  }

  rule {
    description = "All TCP outbound"
    direction   = "out"
    protocol    = "tcp"
    port        = "1-65535"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "All UDP outbound"
    direction   = "out"
    protocol    = "udp"
    port        = "1-65535"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    description = "ICMP outbound"
    direction   = "out"
    protocol    = "icmp"
    source_ips  = []
    destination_ips = ["0.0.0.0/0", "::/0"]
  }
}

# ── Server ───────────────────────────────────────────────────────────────

resource "hcloud_server" "this" {
  name        = "${var.name_prefix}-${replace(var.domain, ".", "-")}"
  image       = "ubuntu-22.04"
  server_type = var.instance_size
  location    = var.region
  ssh_keys    = [hcloud_ssh_key.this.id]
  firewall_ids = [hcloud_firewall.this.id]

  labels = {
    project = var.name_prefix
    domain  = replace(var.domain, ".", "-")
  }

  user_data = <<-CLOUD_INIT
    #!/bin/bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    # ── System updates ───────────────────────────────────────────────────
    apt-get update -qq
    apt-get upgrade -y -qq

    # ── Install Docker via official repo (not snap) ──────────────────────
    apt-get install -y -qq ca-certificates curl gnupg lsb-release git
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

    systemctl enable docker
    systemctl start docker

    # ── Clone InfraGuard and build Docker image ──────────────────────────
    git clone ${var.repo_url} /opt/infraguard
    cd /opt/infraguard

    mkdir -p /opt/infraguard/data /opt/infraguard/rules

    docker compose build

    # ── Signal ready for config deployment ───────────────────────────────
    touch /var/lib/infraguard-bootstrap-done
  CLOUD_INIT
}
