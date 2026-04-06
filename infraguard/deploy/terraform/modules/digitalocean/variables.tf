variable "domain" {
  type        = string
  description = "Primary domain for this redirector instance"
}

variable "ssh_key_fingerprint" {
  type        = string
  description = "MD5 fingerprint of the operator's SSH public key (already registered on DO account)"
}

variable "operator_ip" {
  type        = string
  description = "Operator IP allowed for SSH access (CIDR notation, e.g. 1.2.3.4/32)"
}

variable "instance_size" {
  type        = string
  default     = "s-1vcpu-1gb"
  description = "DigitalOcean Droplet size slug"
}

variable "region" {
  type        = string
  default     = "nyc1"
  description = "DigitalOcean region slug"
}

variable "repo_url" {
  type        = string
  default     = "https://github.com/Whispergate/InfraGuard.git"
  description = "Git repository URL for InfraGuard source code"
}

variable "name_prefix" {
  type        = string
  default     = "infraguard"
  description = "Name prefix applied to all provisioned DigitalOcean resources"
}
