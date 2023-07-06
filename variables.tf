#ECS cluster/task settings
variable "app_name" {
  type        = string
  description = "Name of the proxy scanner app and components"
  default     = "tf-lacework-proxy-scanner"
}

variable "app_port" {
  type        = number
  description = "Ports to open to allow webhook to reach proxy scanner"
  default     = 8080
}

variable "lb_port" {
  type        = number
  description = "Ports to open to allow inbound webhooks to app load balancer"
  default     = 443
}

variable "image_name" {
  type        = string
  description = "Proxy scanner image"
  default     = "lacework/lacework-proxy-scanner"
}

variable "image_tag" {
  type        = string
  description = "Proxy scanner image tag"
  default     = "latest"
}

variable "min_count" {
  type        = number
  description = "Minimum number of proxy scanners to run at any given time"
  default     = 1
}

variable "max_count" {
  type        = number
  description = "Maximum number of proxy scanners to run when autoscaling is triggered"
  default     = 4
}

variable "mem" {
  type        = number
  description = "Memory allocation for each proxy-scanner container"
  default     = 2048
}

variable "cpu" {
  type        = number
  description = "CPU allocation for each proxy-scanner container"
  default     = 1024
}

variable "mem_threshold" {
  type        = number
  description = "Average percentage memory utilization threshold when autoscaling will kick in"
  default     = 80
}

variable "cpu_threshold" {
  type        = number
  description = "Average percentage cpu utilization threshold when autoscaling will kick in"
  default     = 60
}

variable "force_new_deployment" {
  type        = bool
  description = "Force new containers to be created"
  default     = true
}

variable "use_existing_network" {
  type        = bool
  description = "Should the module use existing networking resources (vpc, internet gateway, route table, subnets, etc) or create new ones."
  default     = true
}

variable "vpc_id" {
  type    = string
  default = ""
}

variable "vpc_cidr_block" {
  type    = string
  default = "10.10.32.0/24"
}

variable "subnet_cidr_block_1" {
  type    = string
  default = "10.10.32.0/25"
}

variable "subnet_cidr_block_2" {
  type    = string
  default = "10.10.32.128/25"
}

variable "az_1" {
  type    = string
  default = "us-east-1a"
}

variable "az_2" {
  type    = string
  default = "us-east-1b"
}

#variable "use_existing_subnet" {
#  type    = bool
#  default = true
#}

#variable "subnet_id" {
#  type    = string
#  default = ""
#}

variable "use_existing_execution_role" {
  type    = bool
  default = false
}

variable "execution_role_arn" {
  type    = string
  default = ""
}

variable "use_existing_task_role" {
  type    = bool
  default = false
}

variable "task_role_arn" {
  type    = string
  default = ""
}

variable "enable_logging" {
  type        = bool
  description = "Enable logging for the proxy scanner containers with CloudWatch. Default is enabled."
  default     = true
}

#certificate management
variable "use_existing_cert" {
  type        = bool
  description = "True if a cert exists that will be provided to the module for load balancer HTTPS. If false, a self-signed cert will be created by default."
  default     = false
}

variable "use_existing_acm_cert" {
  type        = bool
  description = "True if cert exists in AWS ACM. Requires 'certificate_arn' to provid load balancer with cert. False if providing certificate files to the module (use private_key, certificate, and issuer variables) in this case."
  default     = false
}

variable "issuer" {
  type        = string
  description = "Root certificate (issuer) for load balancer https"
  default     = ""
}

variable "certificate" {
  type        = string
  description = "Certificate body for load balancer https"
  default     = ""
}

variable "private_key" {
  type        = string
  description = "Certificate key for load balancer https"
  default     = ""
}

variable "certificate_arn" {
  type        = string
  description = "An existing AWS ACM certificate to use with the load balancer for https. Works when 'use_existing_acm_cert' is true"
  default     = ""
}

#Lacework proxy scanner settings
variable "proxy_scanner_token" {
  type        = string
  description = "The token for the Lacework proxy scanner."
}

variable "lacework_account_name" {
  type        = string
  description = "The name of your Lacework account (for the proxy scanner)."
}

variable "static_cache_location" {
  type        = string
  description = "Location of the proxy scanner's cache file."
  default     = "/opt/lacework/cache"
}

variable "scan_public_registries" {
  type        = bool
  description = "Set to true if you want to scan images from registries that are publicly accessible."
  default     = false
}

variable "registries" {
  type        = list(any)
  description = "A list of registries to apply to proxy scanner. See proxy scanner configuration documentation for details."
}

