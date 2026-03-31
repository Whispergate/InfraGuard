output "instance_ip" {
  value       = var.upstream_url
  description = "Backend VPS URL (Workers relay to this address)"
}

output "instance_id" {
  value       = cloudflare_workers_script.relay.name
  description = "Cloudflare Worker script name"
}

output "ssh_command" {
  value       = "# N/A — Cloudflare Workers have no SSH access. Connect to your backend VPS instead."
  description = "Not applicable for Workers — relay front only"
}

output "worker_route" {
  value       = cloudflare_workers_route.relay.pattern
  description = "URL pattern the Worker handles"
}
