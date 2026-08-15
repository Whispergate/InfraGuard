output "instance_ip" {
  value       = hcloud_server.this.ipv4_address
  description = "Public IPv4 address of the Hetzner Cloud server"
}

output "instance_id" {
  value       = hcloud_server.this.id
  description = "Hetzner Cloud server numeric ID"
}

output "ssh_command" {
  value       = "ssh root@${hcloud_server.this.ipv4_address}"
  description = "SSH command to connect to the server as root (Hetzner default)"
}
