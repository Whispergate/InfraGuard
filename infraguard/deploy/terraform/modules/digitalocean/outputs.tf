output "instance_ip" {
  value       = digitalocean_droplet.this.ipv4_address
  description = "Public IPv4 address of the DigitalOcean Droplet"
}

output "instance_id" {
  value       = digitalocean_droplet.this.id
  description = "DigitalOcean Droplet numeric ID"
}

output "ssh_command" {
  value       = "ssh root@${digitalocean_droplet.this.ipv4_address}"
  description = "SSH command to connect to the Droplet as root (DigitalOcean default)"
}
