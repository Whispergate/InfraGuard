"""Shared cloud-init bootstrap script for all providers."""


def bootstrap_script(repo_url: str) -> str:
    """Return a cloud-init script that installs Docker and builds InfraGuard.

    Does not embed API tokens, SSH keys, or env files. Those are deployed
    post-provision via SSH/SCP by the rotation pipeline or the Ansible role.
    """
    return f"""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get upgrade -y -qq

# Install Docker via official repo
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

# Clone InfraGuard and build
git clone {repo_url} /opt/infraguard
cd /opt/infraguard
mkdir -p /opt/infraguard/data /opt/infraguard/rules
docker compose build

# Signal ready for config deployment
touch /var/lib/infraguard-bootstrap-done
"""
