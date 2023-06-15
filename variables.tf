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

variable "task_count" {
  type        = number
  description = "Number of proxy scanner tasks to run"
  default     = 1
}

variable "force_new_deployment" {
  type        = bool
  description = "Force new containers to be created"
  default     = true
}

variable "use_existing_vpc" {
  type    = bool
  default = true
}

variable "vpc_id" {
  type = string
  #default = "vpc-002ac2fb315c88fb3"
  default = ""
}

variable "vpc_cidr_block" {
  type    = string
  default = "10.10.32.0/24"
}

variable "use_existing_subnet" {
  type    = bool
  default = true
}

variable "subnet_id" {
  type    = string
  default = ""
}

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

