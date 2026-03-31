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
  default     = "s-1vcpu-1gb"
  description = "DigitalOcean Droplet size slug"
}

variable "region" {
  type        = string
  default     = "nyc1"
  description = "DigitalOcean region slug"
}

variable "docker_image" {
  type        = string
  default     = "infraguard:latest"
  description = "Docker image to run (registry image or 'infraguard:latest' to build from source)"
}

variable "name_prefix" {
  type        = string
  default     = "infraguard"
  description = "Name prefix applied to all provisioned DigitalOcean resources"
}
