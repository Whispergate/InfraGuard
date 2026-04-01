terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.10"
}

provider "azurerm" {
  features {}
}

# ── Resource group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "this" {
  name     = "${var.name_prefix}-${var.domain}-rg"
  location = var.region

  tags = {
    project = var.name_prefix
    domain  = var.domain
  }
}

# ── Virtual network + subnet ──────────────────────────────────────────────────

resource "azurerm_virtual_network" "this" {
  name                = "${var.name_prefix}-${var.domain}-vnet"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  address_space       = ["10.0.0.0/16"]

  tags = {
    project = var.name_prefix
    domain  = var.domain
  }
}

resource "azurerm_subnet" "this" {
  name                 = "${var.name_prefix}-${var.domain}-subnet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.1.0/24"]
}

# ── Public IP ─────────────────────────────────────────────────────────────────

resource "azurerm_public_ip" "this" {
  name                = "${var.name_prefix}-${var.domain}-pip"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    project = var.name_prefix
    domain  = var.domain
  }
}

# ── Network security group ────────────────────────────────────────────────────
# Rules:
#   - TCP 80/443 inbound from anywhere (public C2 traffic)
#   - TCP 22 inbound from operator_ip ONLY (no public SSH)
#   - Deny all other inbound (explicit deny rule at lowest priority wins)

resource "azurerm_network_security_group" "this" {
  name                = "${var.name_prefix}-${var.domain}-nsg"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location

  security_rule {
    name                       = "allow-http"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Allow HTTP inbound for redirector"
  }

  security_rule {
    name                       = "allow-https"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Allow HTTPS inbound for redirector"
  }

  security_rule {
    name                       = "allow-ssh-operator-only"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.operator_ip
    destination_address_prefix = "*"
    description                = "Allow SSH from operator IP only - never 0.0.0.0/0"
  }

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Deny all other inbound traffic"
  }

  tags = {
    project = var.name_prefix
    domain  = var.domain
  }
}

# ── Network interface ─────────────────────────────────────────────────────────

resource "azurerm_network_interface" "this" {
  name                = "${var.name_prefix}-${var.domain}-nic"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.this.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.this.id
  }

  tags = {
    project = var.name_prefix
    domain  = var.domain
  }
}

resource "azurerm_network_interface_security_group_association" "this" {
  network_interface_id      = azurerm_network_interface.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

# ── Linux virtual machine ─────────────────────────────────────────────────────
# custom_data contains the cloud-init bootstrap script (base64-encoded by Terraform).
# IMPORTANT: Do NOT embed API tokens or secrets in custom_data - they are visible
# in the Azure portal. Post-provision secrets via SSH or Azure Key Vault.

resource "azurerm_linux_virtual_machine" "this" {
  name                = "${var.name_prefix}-${var.domain}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  size                = var.instance_size
  admin_username      = "operator"

  network_interface_ids = [
    azurerm_network_interface.this.id,
  ]

  admin_ssh_key {
    username   = "operator"
    public_key = var.ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 30
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(<<-CLOUD_INIT
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
    DOCKER_IMAGE="${var.docker_image}"
    if echo "$DOCKER_IMAGE" | grep -q '/'; then
      docker pull "$DOCKER_IMAGE"
    else
      apt-get install -y -qq git
      git clone https://github.com/Whispergate/InfraGuard.git /opt/infraguard
      docker build -t "$DOCKER_IMAGE" /opt/infraguard
    fi

    # ── Signal provisioning complete ─────────────────────────────────────────
    touch /var/lib/infraguard-bootstrap-done
  CLOUD_INIT
  )

  tags = {
    Name    = "${var.name_prefix}-${var.domain}"
    project = var.name_prefix
    domain  = var.domain
  }
}
