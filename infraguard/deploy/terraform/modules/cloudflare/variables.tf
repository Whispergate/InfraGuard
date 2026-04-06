variable "domain" {
  type        = string
  description = "Domain managed in Cloudflare (must already exist as a zone)"
}

variable "upstream_url" {
  type        = string
  description = "Backend VPS URL to relay traffic to (e.g. https://1.2.3.4)"
}

variable "route_pattern" {
  type        = string
  default     = "*"
  description = "URL pattern the Worker handles (e.g. '*' for all traffic on the domain)"
}

variable "worker_name" {
  type        = string
  default     = "infraguard-relay"
  description = "Name of the Cloudflare Worker script"
}

variable "name_prefix" {
  type        = string
  default     = "infraguard"
  description = "Name prefix applied to Cloudflare resources"
}
