variable "domain" {
  type        = string
  description = "Primary domain for this redirector instance"
}

variable "ssh_public_key" {
  type        = string
  sensitive   = true
  description = "SSH public key for operator access"
}

variable "operator_ip" {
  type        = string
  description = "Operator IP allowed for SSH access (CIDR notation, e.g. 1.2.3.4/32)"
}

variable "instance_size" {
  type        = string
  default     = "Standard_B1s"
  description = "Azure VM size (SKU)"
}

variable "region" {
  type        = string
  default     = "eastus"
  description = "Azure region to deploy in"
}

variable "docker_image" {
  type        = string
  default     = "infraguard:latest"
  description = "Docker image to run (registry image or 'infraguard:latest' to build from source)"
}

variable "name_prefix" {
  type        = string
  default     = "infraguard"
  description = "Name prefix applied to all provisioned Azure resources"
}
