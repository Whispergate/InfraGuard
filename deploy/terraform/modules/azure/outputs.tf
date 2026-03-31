output "instance_ip" {
  value       = azurerm_public_ip.this.ip_address
  description = "Public IPv4 address of the Azure VM"
}

output "instance_id" {
  value       = azurerm_linux_virtual_machine.this.id
  description = "Azure resource ID of the Linux virtual machine"
}

output "ssh_command" {
  value       = "ssh operator@${azurerm_public_ip.this.ip_address}"
  description = "SSH command to connect to the instance as the provisioned operator user"
}
