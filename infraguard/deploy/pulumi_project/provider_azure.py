"""Azure provider: Linux VM + NSG + VNet + public IP."""

import pulumi
import pulumi_azure_native as azure
from pulumi_azure_native import compute, network, resources

from cloud_init import bootstrap_script
import base64


def provision(cfg: dict) -> dict:
    prefix = cfg["name_prefix"]
    domain = cfg["domain"]
    resource_name = f"{prefix}-{domain}"
    location = cfg.get("region", "eastus")

    tags = {"project": prefix, "domain": domain}

    rg = resources.ResourceGroup(
        "redirector-rg",
        resource_group_name=f"{resource_name}-rg",
        location=location,
        tags=tags,
    )

    vnet = network.VirtualNetwork(
        "redirector-vnet",
        virtual_network_name=f"{resource_name}-vnet",
        resource_group_name=rg.name,
        location=rg.location,
        address_space=network.AddressSpaceArgs(
            address_prefixes=["10.0.0.0/16"],
        ),
        tags=tags,
    )

    subnet = network.Subnet(
        "redirector-subnet",
        subnet_name=f"{resource_name}-subnet",
        resource_group_name=rg.name,
        virtual_network_name=vnet.name,
        address_prefix="10.0.1.0/24",
    )

    public_ip = network.PublicIPAddress(
        "redirector-pip",
        public_ip_address_name=f"{resource_name}-pip",
        resource_group_name=rg.name,
        location=rg.location,
        public_ip_allocation_method=network.IPAllocationMethod.STATIC,
        sku=network.PublicIPAddressSkuArgs(
            name=network.PublicIPAddressSkuName.STANDARD,
        ),
        tags=tags,
    )

    nsg_rules = [
        network.SecurityRuleArgs(
            name="allow-http",
            priority=100,
            direction=network.SecurityRuleDirection.INBOUND,
            access=network.SecurityRuleAccess.ALLOW,
            protocol=network.SecurityRuleProtocol.TCP,
            source_port_range="*",
            destination_port_range="80",
            source_address_prefix="*",
            destination_address_prefix="*",
        ),
        network.SecurityRuleArgs(
            name="allow-https",
            priority=101,
            direction=network.SecurityRuleDirection.INBOUND,
            access=network.SecurityRuleAccess.ALLOW,
            protocol=network.SecurityRuleProtocol.TCP,
            source_port_range="*",
            destination_port_range="443",
            source_address_prefix="*",
            destination_address_prefix="*",
        ),
        network.SecurityRuleArgs(
            name="allow-ssh-operator",
            priority=102,
            direction=network.SecurityRuleDirection.INBOUND,
            access=network.SecurityRuleAccess.ALLOW,
            protocol=network.SecurityRuleProtocol.TCP,
            source_port_range="*",
            destination_port_range="22",
            source_address_prefix=cfg["operator_ip"],
            destination_address_prefix="*",
        ),
        network.SecurityRuleArgs(
            name="deny-all-inbound",
            priority=4096,
            direction=network.SecurityRuleDirection.INBOUND,
            access=network.SecurityRuleAccess.DENY,
            protocol=network.SecurityRuleProtocol.ASTERISK,
            source_port_range="*",
            destination_port_range="*",
            source_address_prefix="*",
            destination_address_prefix="*",
        ),
    ]

    for i, cidr in enumerate(cfg.get("dashboard_cidrs", [])):
        nsg_rules.insert(-1, network.SecurityRuleArgs(
            name=f"allow-dashboard-{i}",
            priority=200 + i,
            direction=network.SecurityRuleDirection.INBOUND,
            access=network.SecurityRuleAccess.ALLOW,
            protocol=network.SecurityRuleProtocol.TCP,
            source_port_range="*",
            destination_port_range="8080",
            source_address_prefix=cidr,
            destination_address_prefix="*",
        ))

    nsg = network.NetworkSecurityGroup(
        "redirector-nsg",
        network_security_group_name=f"{resource_name}-nsg",
        resource_group_name=rg.name,
        location=rg.location,
        security_rules=nsg_rules,
        tags=tags,
    )

    nic = network.NetworkInterface(
        "redirector-nic",
        network_interface_name=f"{resource_name}-nic",
        resource_group_name=rg.name,
        location=rg.location,
        ip_configurations=[
            network.NetworkInterfaceIPConfigurationArgs(
                name="primary",
                subnet=network.SubnetArgs(id=subnet.id),
                private_ip_allocation_method=network.IPAllocationMethod.DYNAMIC,
                public_ip_address=network.PublicIPAddressArgs(id=public_ip.id),
            ),
        ],
        network_security_group=network.NetworkSecurityGroupArgs(id=nsg.id),
        tags=tags,
    )

    user_data_b64 = base64.b64encode(
        bootstrap_script(cfg["repo_url"]).encode()
    ).decode()

    vm = compute.VirtualMachine(
        "redirector",
        vm_name=f"{resource_name}",
        resource_group_name=rg.name,
        location=rg.location,
        hardware_profile=compute.HardwareProfileArgs(
            vm_size=cfg.get("instance_size", "Standard_B1s"),
        ),
        os_profile=compute.OSProfileArgs(
            computer_name=prefix,
            admin_username="operator",
            custom_data=user_data_b64,
            linux_configuration=compute.LinuxConfigurationArgs(
                disable_password_authentication=True,
                ssh=compute.SshConfigurationArgs(
                    public_keys=[
                        compute.SshPublicKeyArgs(
                            path="/home/operator/.ssh/authorized_keys",
                            key_data=cfg["ssh_public_key"],
                        ),
                    ],
                ),
            ),
        ),
        storage_profile=compute.StorageProfileArgs(
            os_disk=compute.OSDiskArgs(
                create_option=compute.DiskCreateOptionTypes.FROM_IMAGE,
                managed_disk=compute.ManagedDiskParametersArgs(
                    storage_account_type=compute.StorageAccountTypes.STANDARD_LRS,
                ),
                disk_size_gb=30,
            ),
            image_reference=compute.ImageReferenceArgs(
                publisher="Canonical",
                offer="0001-com-ubuntu-server-jammy",
                sku="22_04-lts-gen2",
                version="latest",
            ),
        ),
        network_profile=compute.NetworkProfileArgs(
            network_interfaces=[
                compute.NetworkInterfaceReferenceArgs(id=nic.id, primary=True),
            ],
        ),
        tags=tags,
    )

    return {
        "instance_ip": public_ip.ip_address,
        "instance_id": vm.id,
        "ssh_user": "operator",
        "ssh_command": public_ip.ip_address.apply(
            lambda ip: f"ssh operator@{ip}" if ip else "pending..."
        ),
        "dashboard_url": public_ip.ip_address.apply(
            lambda ip: f"https://{ip}:8080" if ip else "pending..."
        ),
        "provider": "azure",
    }
