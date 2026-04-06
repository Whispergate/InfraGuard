output "instance_ip" {
  value       = aws_instance.this.public_ip
  description = "Public IPv4 address of the EC2 instance"
}

output "instance_id" {
  value       = aws_instance.this.id
  description = "EC2 instance ID (e.g. i-0abc123def456)"
}

output "ssh_command" {
  value       = "ssh ubuntu@${aws_instance.this.public_ip}"
  description = "SSH command to connect to the instance as the default Ubuntu user"
}
