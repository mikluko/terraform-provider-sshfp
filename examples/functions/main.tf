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
  }
}

# Generate an SSH key pair
resource "tls_private_key" "server" {
  algorithm = "ED25519"
}

# Example using functions directly with Route53
# Functions return just the fingerprint hex string
resource "aws_route53_record" "sshfp_sha256" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # Manually construct the SSHFP record: "4 2 fingerprint" for Ed25519 SHA-256
  records = ["4 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)}"]
}

# Example with both SHA-1 and SHA-256 for compatibility
resource "aws_route53_record" "sshfp_both" {
  zone_id = var.zone_id
  name    = "legacy.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  records = [
    "4 1 ${provider::sshfp::sha1_fingerprint(tls_private_key.server.public_key_openssh)}",
    "4 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)}"
  ]
}

# Example with RSA key
resource "tls_private_key" "rsa_server" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_route53_record" "sshfp_rsa" {
  zone_id = var.zone_id
  name    = "rsa-server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # RSA is algorithm 1
  records = ["1 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.rsa_server.public_key_openssh)}"]
}

variable "zone_id" {
  description = "The Route53 zone ID where SSHFP records will be created"
  type        = string
}

output "ed25519_fingerprint_sha256" {
  description = "The SHA-256 fingerprint for the Ed25519 key"
  value       = provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)
}

output "ed25519_fingerprint_sha1" {
  description = "The SHA-1 fingerprint for the Ed25519 key"
  value       = provider::sshfp::sha1_fingerprint(tls_private_key.server.public_key_openssh)
}