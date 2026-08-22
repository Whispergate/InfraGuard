"""Hetzner Cloud provider: server + firewall + SSH key."""

import pulumi
import pulumi_hcloud as hcloud

from cloud_init import bootstrap_script


def provision(cfg: dict) -> dict:
    prefix = cfg["name_prefix"]
    domain = cfg["domain"]
    resource_name = f"{prefix}-{domain.replace('.', '-')}"

    labels = {"project": prefix, "domain": domain.replace(".", "-")}

    ssh_key = hcloud.SshKey(
        "redirector-key",
        name=f"{resource_name}-key",
        public_key=cfg["ssh_public_key"],
        labels=labels,
    )

    fw_rules = [
        hcloud.FirewallRuleArgs(
            description="HTTP inbound",
            direction="in",
            protocol="tcp",
            port="80",
            source_ips=["0.0.0.0/0", "::/0"],
        ),
        hcloud.FirewallRuleArgs(
            description="HTTPS inbound",
            direction="in",
            protocol="tcp",
            port="443",
            source_ips=["0.0.0.0/0", "::/0"],
        ),
        hcloud.FirewallRuleArgs(
            description="SSH from operator only",
            direction="in",
            protocol="tcp",
            port="22",
            source_ips=[cfg["operator_ip"]],
        ),
        hcloud.FirewallRuleArgs(
            description="All TCP outbound",
            direction="out",
            protocol="tcp",
            port="1-65535",
            destination_ips=["0.0.0.0/0", "::/0"],
        ),
        hcloud.FirewallRuleArgs(
            description="All UDP outbound",
            direction="out",
            protocol="udp",
            port="1-65535",
            destination_ips=["0.0.0.0/0", "::/0"],
        ),
        hcloud.FirewallRuleArgs(
            description="ICMP outbound",
            direction="out",
            protocol="icmp",
            destination_ips=["0.0.0.0/0", "::/0"],
        ),
    ]

    for cidr in cfg.get("dashboard_cidrs", []):
        fw_rules.append(
            hcloud.FirewallRuleArgs(
                description="Dashboard from operator",
                direction="in",
                protocol="tcp",
                port="8080",
                source_ips=[cidr],
            )
        )

    firewall = hcloud.Firewall(
        "redirector-fw",
        name=f"{resource_name}-fw",
        rules=fw_rules,
        labels=labels,
    )

    server = hcloud.Server(
        "redirector",
        name=resource_name,
        image="ubuntu-22.04",
        server_type=cfg.get("instance_size", "cx22"),
        location=cfg.get("region", "fsn1"),
        ssh_keys=[ssh_key.id],
        firewall_ids=[firewall.id],
        user_data=bootstrap_script(cfg["repo_url"]),
        labels=labels,
    )

    return {
        "instance_ip": server.ipv4_address,
        "instance_id": server.id,
        "ssh_user": "root",
        "ssh_command": server.ipv4_address.apply(lambda ip: f"ssh root@{ip}"),
        "dashboard_url": server.ipv4_address.apply(lambda ip: f"https://{ip}:8080"),
        "provider": "hetzner",
    }
