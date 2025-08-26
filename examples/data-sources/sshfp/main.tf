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

# Use data source to get both SHA-1 and SHA-256 fingerprints
data "sshfp_fingerprint" "server" {
  public_key = tls_private_key.server.public_key_openssh
}

# Example with AWS Route53 (needs full record string)
resource "aws_route53_record" "sshfp" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # Use both SHA-1 and SHA-256 records
  records = [
    data.sshfp_fingerprint.server.record_sha1,
    data.sshfp_fingerprint.server.record_sha256
  ]
}

# Example with Cloudflare (needs separate components)
resource "cloudflare_record" "sshfp_sha256" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm   = data.sshfp_fingerprint.server.algorithm
    type        = 2  # SHA-256
    fingerprint = data.sshfp_fingerprint.server.sha256
  }
}

resource "cloudflare_record" "sshfp_sha1" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm   = data.sshfp_fingerprint.server.algorithm
    type        = 1  # SHA-1
    fingerprint = data.sshfp_fingerprint.server.sha1
  }
}

# Example with different key types
resource "tls_private_key" "rsa_server" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "sshfp_fingerprint" "rsa" {
  public_key = tls_private_key.rsa_server.public_key_openssh
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
    algorithm      = data.sshfp_fingerprint.server.algorithm
    algorithm_name = data.sshfp_fingerprint.server.algorithm_name
    sha1           = data.sshfp_fingerprint.server.sha1
    sha256         = data.sshfp_fingerprint.server.sha256
    record_sha1    = data.sshfp_fingerprint.server.record_sha1
    record_sha256  = data.sshfp_fingerprint.server.record_sha256
  }
}

output "rsa_algorithm_name" {
  value = data.sshfp_fingerprint.rsa.algorithm_name
}

output "ecdsa_records" {
  value = {
    sha1   = data.sshfp_fingerprint.ecdsa.record_sha1
    sha256 = data.sshfp_fingerprint.ecdsa.record_sha256
  }
}

variable "zone_id" {
  description = "The Route53 zone ID"
  type        = string
}

variable "cloudflare_zone_id" {
  description = "The Cloudflare zone ID"
  type        = string
}