terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.81"
    }
}
  required_version = ">= 1.10"
}

# ── SSH key ───────────────────────────────────────────────────────────────────
# The operator's SSH key fingerprint is computed by the CLI from the public
# key file and passed directly.  The key must already exist on the DO account.
# This avoids 422 "SSH Key is already in use" errors from trying to re-create
# an existing key, and works regardless of what name the key was registered
# under.
#
# If the key doesn't exist yet, add it first:
#   doctl compute ssh-key import infraguard --public-key-file ~/.ssh/id_rsa.pub

# ── Tag ───────────────────────────────────────────────────────────────────────
# The Droplet is tagged at creation time so the firewall attaches immediately.
# This eliminates the exposure window described in RESEARCH.md Pitfall 2 - the
# firewall is applied at Droplet creation via tag membership, not as a separate
# post-creation association step.

resource "digitalocean_tag" "this" {
  name = "${var.name_prefix}-${replace(var.domain, ".", "-")}"
}

# ── Firewall ──────────────────────────────────────────────────────────────────
# Tag-based attachment: any Droplet with this tag automatically gets these rules.
# Rules:
#   - TCP 80/443 inbound from anywhere (public C2 traffic)
#   - TCP 22 inbound from operator_ip ONLY
#   - All outbound (Docker pulls, apt, upstream C2 comms)

resource "digitalocean_firewall" "this" {
  name = "${var.name_prefix}-${var.domain}-fw"
  tags = [digitalocean_tag.this.id]

  # HTTP inbound
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # HTTPS inbound
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # SSH restricted to operator IP - NEVER 0.0.0.0/0
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = [var.operator_ip]
  }

  # All TCP outbound (Docker pulls, apt updates, upstream C2)
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # All UDP outbound (DNS)
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # ICMP outbound (ping for diagnostics)
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ── Droplet ───────────────────────────────────────────────────────────────────
# The Droplet is tagged at creation time (tags attribute), which causes the
# digitalocean_firewall to apply immediately - no exposure window.
# IMPORTANT (Pitfall 4): Do NOT embed API tokens or secrets in user_data.
# Post-provision secrets via SSH after Droplet is ready.

resource "digitalocean_droplet" "this" {
  name   = "${var.name_prefix}-${replace(var.domain, ".", "-")}"
  image  = "ubuntu-22-04-x64"
  size   = var.instance_size
  region = var.region

  ssh_keys = [var.ssh_key_fingerprint]

  # Attaches the firewall at creation via tag - zero exposure window
  tags = [digitalocean_tag.this.id]

  user_data = <<-CLOUD_INIT
    #!/bin/bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    # ── System updates ───────────────────────────────────────────────────────
    apt-get update -qq
    apt-get upgrade -y -qq

    # ── Install Docker via official repo (not snap) ──────────────────────────
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

    # ── Clone InfraGuard and build Docker image ──────────────────────────────
    git clone ${var.repo_url} /opt/infraguard
    cd /opt/infraguard

    # Create runtime directories (mounted as volumes by docker-compose)
    mkdir -p /opt/infraguard/data /opt/infraguard/rules

    # Build the image using the repo's Dockerfile
    docker compose build

    # ── Signal ready for config deployment ───────────────────────────────────
    # The CLI polls for this file over SSH before deploying config + starting
    touch /var/lib/infraguard-bootstrap-done
  CLOUD_INIT
}
