terraform {
  required_providers {
    sshfp = {
      source = "mikluko/sshfp"
    }
    tls = {
      source = "hashicorp/tls"
    }
    aws = {
      source = "hashicorp/aws"
    }
    cloudflare = {
      source = "cloudflare/cloudflare"
    }
  }
}

# Generate an SSH key pair
resource "tls_private_key" "server" {
  algorithm = "ED25519"
}

# Use data source to get SSHFP components
data "sshfp_fingerprint" "server_sha256" {
  public_key       = tls_private_key.server.public_key_openssh
  fingerprint_type = 2  # SHA-256 (optional, defaults to 2)
}

data "sshfp_fingerprint" "server_sha1" {
  public_key       = tls_private_key.server.public_key_openssh
  fingerprint_type = 1  # SHA-1
}

# Example with AWS Route53 (needs full record string)
resource "aws_route53_record" "sshfp" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # Use the pre-formatted record from data source
  records = [
    data.sshfp_fingerprint.server_sha256.record,
    data.sshfp_fingerprint.server_sha1.record
  ]
}

# Example with Cloudflare (needs separate components)
resource "cloudflare_record" "sshfp_sha256" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm   = data.sshfp_fingerprint.server_sha256.algorithm
    type        = data.sshfp_fingerprint.server_sha256.fingerprint_type
    fingerprint = data.sshfp_fingerprint.server_sha256.fingerprint
  }
}

resource "cloudflare_record" "sshfp_sha1" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm   = data.sshfp_fingerprint.server_sha1.algorithm
    type        = data.sshfp_fingerprint.server_sha1.fingerprint_type
    fingerprint = data.sshfp_fingerprint.server_sha1.fingerprint
  }
}

# Example with different key types
resource "tls_private_key" "rsa_server" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "sshfp_fingerprint" "rsa" {
  public_key = tls_private_key.rsa_server.public_key_openssh
  # fingerprint_type defaults to 2 (SHA-256)
}

resource "tls_private_key" "ecdsa_server" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

data "sshfp_fingerprint" "ecdsa" {
  public_key = tls_private_key.ecdsa_server.public_key_openssh
}

# Outputs to show the data source attributes
output "ed25519_details" {
  value = {
    algorithm      = data.sshfp_fingerprint.server_sha256.algorithm
    algorithm_name = data.sshfp_fingerprint.server_sha256.algorithm_name
    fingerprint    = data.sshfp_fingerprint.server_sha256.fingerprint
    record         = data.sshfp_fingerprint.server_sha256.record
  }
}

output "rsa_algorithm_name" {
  value = data.sshfp_fingerprint.rsa.algorithm_name
}

output "ecdsa_record" {
  value = data.sshfp_fingerprint.ecdsa.record
}

variable "zone_id" {
  description = "The Route53 zone ID"
  type        = string
}

variable "cloudflare_zone_id" {
  description = "The Cloudflare zone ID"
  type        = string
}