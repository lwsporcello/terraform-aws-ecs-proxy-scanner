resource "tls_private_key" "ca" {
  count     = var.use_existing_cert ? 0 : 1
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  count                 = var.use_existing_cert ? 0 : 1
  private_key_pem       = tls_private_key.ca[0].private_key_pem
  validity_period_hours = 2400000
  is_ca_certificate     = true
  allowed_uses = [
    "cert_signing",
    "key_encipherment",
    "digital_signature",
  ]
  subject {
    common_name = "lacework_ca"
  }
}

resource "tls_private_key" "proxy-scanner" {
  count     = var.use_existing_cert ? 0 : 1
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "proxy-scanner" {
  count           = var.use_existing_cert ? 0 : 1
  private_key_pem = tls_private_key.proxy-scanner[0].private_key_pem
  dns_names = [
    "proxy-scanner.lacework.svc",
  ]
  subject {
    common_name = "lacework-proxy-scanner.lacework.svc"
  }
}

resource "tls_locally_signed_cert" "proxy-scanner" {
  count = var.use_existing_cert ? 0 : 1
  allowed_uses = [
    "cert_signing",
    "key_encipherment",
    "digital_signature",
    "client_auth",
    "server_auth"
  ]
  ca_cert_pem           = tls_self_signed_cert.ca[0].cert_pem
  ca_private_key_pem    = tls_private_key.ca[0].private_key_pem
  cert_request_pem      = tls_cert_request.proxy-scanner[0].cert_request_pem
  validity_period_hours = 2400000
}
