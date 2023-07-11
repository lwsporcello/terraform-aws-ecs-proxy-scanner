output "config" {
  value       = local.config
  description = "Proxy Scanner Config"
}

output "vpc" {
  value = data.aws_vpc.vpc
}

