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
  default     = "cx22"
  description = "Hetzner Cloud server type (e.g. cx22, cx32, cx42)"
}

variable "region" {
  type        = string
  default     = "fsn1"
  description = "Hetzner Cloud datacenter location (e.g. fsn1, nbg1, hel1, ash)"
}

variable "repo_url" {
  type        = string
  default     = "https://github.com/Whispergate/InfraGuard.git"
  description = "Git repository URL for InfraGuard source code"
}

variable "name_prefix" {
  type        = string
  default     = "infraguard"
  description = "Name prefix applied to all provisioned Hetzner resources"
}
