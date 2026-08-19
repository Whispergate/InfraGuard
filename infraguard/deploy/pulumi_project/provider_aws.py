"""AWS provider: EC2 instance + security group + key pair."""

import pulumi
import pulumi_aws as aws

from cloud_init import bootstrap_script


def provision(cfg: dict) -> dict:
    prefix = cfg["name_prefix"]
    domain = cfg["domain"]
    resource_name = f"{prefix}-{domain}"

    tags = {"Name": resource_name, "project": prefix, "domain": domain}

    ami = aws.ec2.get_ami(
        most_recent=True,
        owners=["099720109477"],
        filters=[
            aws.ec2.GetAmiFilterArgs(
                name="name",
                values=["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"],
            ),
            aws.ec2.GetAmiFilterArgs(name="virtualization-type", values=["hvm"]),
            aws.ec2.GetAmiFilterArgs(name="architecture", values=["x86_64"]),
        ],
    )

    key_pair = aws.ec2.KeyPair(
        "redirector-key",
        key_name=f"{resource_name}-key",
        public_key=cfg["ssh_public_key"],
        tags=tags,
    )

    sg_ingress = [
        aws.ec2.SecurityGroupIngressArgs(
            description="HTTP inbound",
            from_port=80, to_port=80, protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="HTTPS inbound",
            from_port=443, to_port=443, protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
        ),
        aws.ec2.SecurityGroupIngressArgs(
            description="SSH from operator only",
            from_port=22, to_port=22, protocol="tcp",
            cidr_blocks=[cfg["operator_ip"]],
        ),
    ]

    for cidr in cfg.get("dashboard_cidrs", []):
        sg_ingress.append(
            aws.ec2.SecurityGroupIngressArgs(
                description="Dashboard from operator",
                from_port=8080, to_port=8080, protocol="tcp",
                cidr_blocks=[cidr],
            )
        )

    sg = aws.ec2.SecurityGroup(
        "redirector-sg",
        name=f"{resource_name}-sg",
        description="InfraGuard redirector - web open, SSH restricted",
        ingress=sg_ingress,
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                description="All outbound",
                from_port=0, to_port=0, protocol="-1",
                cidr_blocks=["0.0.0.0/0"],
            ),
        ],
        tags=tags,
    )

    instance = aws.ec2.Instance(
        "redirector",
        ami=ami.id,
        instance_type=cfg.get("instance_size", "t3.micro"),
        key_name=key_pair.key_name,
        vpc_security_group_ids=[sg.id],
        user_data=bootstrap_script(cfg["repo_url"]),
        tags=tags,
    )

    return {
        "instance_ip": instance.public_ip,
        "instance_id": instance.id,
        "ssh_user": "ubuntu",
        "ssh_command": instance.public_ip.apply(lambda ip: f"ssh ubuntu@{ip}"),
        "dashboard_url": instance.public_ip.apply(lambda ip: f"https://{ip}:8080"),
        "provider": "aws",
    }
