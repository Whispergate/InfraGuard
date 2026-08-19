"""InfraGuard Pulumi program. Provisions a redirector on any supported cloud.

Usage:
    cd deploy/pulumi
    pulumi stack init do-nyc1
    pulumi config set infraguard:provider digitalocean
    pulumi config set infraguard:domain cdn.example.com
    pulumi config set infraguard:operator_ip 203.0.113.10/32
    pulumi config set infraguard:ssh_public_key "$(cat ~/.ssh/id_rsa.pub)"
    pulumi config set --secret digitalocean:token dop_v1_xxx
    pulumi up
"""

import json

import pulumi

config = pulumi.Config("infraguard")

provider = config.require("provider")
domain = config.require("domain")
operator_ip = config.require("operator_ip")
ssh_public_key = config.require("ssh_public_key")

cfg = {
    "domain": domain,
    "operator_ip": operator_ip,
    "ssh_public_key": ssh_public_key,
    "region": config.get("region"),
    "instance_size": config.get("instance_size"),
    "repo_url": config.get("repo_url") or "https://github.com/Whispergate/InfraGuard.git",
    "name_prefix": config.get("name_prefix") or "infraguard",
    "dashboard_cidrs": json.loads(config.get("dashboard_cidrs") or "[]"),
}

if provider == "digitalocean":
    from provider_digitalocean import provision
elif provider == "aws":
    from provider_aws import provision
elif provider == "azure":
    from provider_azure import provision
elif provider == "hetzner":
    from provider_hetzner import provision
else:
    raise ValueError(
        f"Unknown provider '{provider}'. "
        f"Supported: digitalocean, aws, azure, hetzner"
    )

outputs = provision(cfg)

pulumi.export("instance_ip", outputs["instance_ip"])
pulumi.export("instance_id", outputs["instance_id"])
pulumi.export("ssh_user", outputs["ssh_user"])
pulumi.export("ssh_command", outputs["ssh_command"])
pulumi.export("dashboard_url", outputs["dashboard_url"])
pulumi.export("provider", outputs["provider"])
pulumi.export("domain", domain)
