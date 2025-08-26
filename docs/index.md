---
page_title: "Provider: SSHFP"
description: |-
  The SSHFP provider generates SSH fingerprints for DNS SSHFP records.
---

# SSHFP Provider

The SSHFP provider generates SSH fingerprints for DNS SSHFP records. It provides both data sources and functions to generate SSHFP fingerprints from SSH public keys for use with any DNS provider.

## Features

- Generate SSHFP fingerprints from SSH public keys
- Support for all SSH key algorithms (RSA, DSA, ECDSA, Ed25519)
- SHA-1 and SHA-256 fingerprint generation
- Works with any DNS provider (AWS Route53, Cloudflare, etc.)

## Example Usage

```terraform
terraform {
  required_providers {
    sshfp = {
      source  = "mikluko/sshfp"
      version = "~> 0.1"
    }
  }
}

provider "sshfp" {}

# Generate SSH key
resource "tls_private_key" "server" {
  algorithm = "ED25519"
}

# Using data source (recommended)
data "sshfp_fingerprint" "server" {
  public_key       = tls_private_key.server.public_key_openssh
  fingerprint_type = 2  # SHA-256 (optional, defaults to 2)
}

# Use with AWS Route53
resource "aws_route53_record" "sshfp" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  records = [data.sshfp_fingerprint.server.record]
}

# Use with Cloudflare (needs separate components)
resource "cloudflare_record" "sshfp" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm   = data.sshfp_fingerprint.server.algorithm
    type        = data.sshfp_fingerprint.server.fingerprint_type
    fingerprint = data.sshfp_fingerprint.server.fingerprint
  }
}

# Using functions (Terraform 1.8+ only)
resource "aws_route53_record" "sshfp_function" {
  zone_id = var.zone_id
  name    = "server2.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # Manually construct SSHFP record with Ed25519 (algorithm 4) and SHA-256 (type 2)
  records = ["4 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)}"]
}
```

## Schema

This provider does not require any configuration.