"""DigitalOcean provider: Droplet + tag-based firewall."""

import pulumi
import pulumi_digitalocean as do

from cloud_init import bootstrap_script


def provision(cfg: dict) -> dict:
    prefix = cfg["name_prefix"]
    domain = cfg["domain"]
    tag_name = f"{prefix}-{domain.replace('.', '-')}"

    tag = do.Tag("redirector-tag", name=tag_name)

    firewall_inbound = [
        do.FirewallInboundRuleArgs(
            protocol="tcp",
            port_range="80",
            source_addresses=["0.0.0.0/0", "::/0"],
        ),
        do.FirewallInboundRuleArgs(
            protocol="tcp",
            port_range="443",
            source_addresses=["0.0.0.0/0", "::/0"],
        ),
        do.FirewallInboundRuleArgs(
            protocol="tcp",
            port_range="22",
            source_addresses=[cfg["operator_ip"]],
        ),
    ]

    for cidr in cfg.get("dashboard_cidrs", []):
        firewall_inbound.append(
            do.FirewallInboundRuleArgs(
                protocol="tcp",
                port_range="8080",
                source_addresses=[cidr],
            )
        )

    firewall = do.Firewall(
        "redirector-fw",
        name=f"{tag_name}-fw",
        tags=[tag.id],
        inbound_rules=firewall_inbound,
        outbound_rules=[
            do.FirewallOutboundRuleArgs(
                protocol="tcp",
                port_range="1-65535",
                destination_addresses=["0.0.0.0/0", "::/0"],
            ),
            do.FirewallOutboundRuleArgs(
                protocol="udp",
                port_range="1-65535",
                destination_addresses=["0.0.0.0/0", "::/0"],
            ),
            do.FirewallOutboundRuleArgs(
                protocol="icmp",
                destination_addresses=["0.0.0.0/0", "::/0"],
            ),
        ],
    )

    ssh_key = do.SshKey(
        "redirector-key",
        name=f"{tag_name}-key",
        public_key=cfg["ssh_public_key"],
    )

    droplet = do.Droplet(
        "redirector",
        name=tag_name,
        image="ubuntu-22-04-x64",
        size=cfg.get("instance_size", "s-1vcpu-1gb"),
        region=cfg.get("region", "nyc1"),
        ssh_keys=[ssh_key.fingerprint],
        tags=[tag.id],
        user_data=bootstrap_script(cfg["repo_url"]),
    )

    return {
        "instance_ip": droplet.ipv4_address,
        "instance_id": droplet.id,
        "ssh_user": "root",
        "ssh_command": droplet.ipv4_address.apply(lambda ip: f"ssh root@{ip}"),
        "dashboard_url": droplet.ipv4_address.apply(lambda ip: f"https://{ip}:8080"),
        "provider": "digitalocean",
    }
