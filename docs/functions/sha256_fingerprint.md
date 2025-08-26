---
page_title: "sha256_fingerprint Function - terraform-provider-sshfp"
subcategory: ""
description: |-
  Generate SHA-256 fingerprint from SSH public key
---

# sha256_fingerprint Function

Generates a SHA-256 fingerprint (hex string) from an SSH public key. This function returns only the fingerprint hex string, allowing you to construct SSHFP records as needed.

## Example Usage

```terraform
# Generate Ed25519 key
resource "tls_private_key" "server" {
  algorithm = "ED25519"
}

# Get SHA-256 fingerprint
output "fingerprint" {
  value = provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)
}

# Use with Route53 - manually construct SSHFP record
# Format: "algorithm type fingerprint"
resource "aws_route53_record" "sshfp" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # Ed25519 (algorithm 4) with SHA-256 (type 2)
  records = ["4 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)}"]
}

# RSA example
resource "tls_private_key" "rsa_server" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_route53_record" "sshfp_rsa" {
  zone_id = var.zone_id
  name    = "rsa-server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # RSA (algorithm 1) with SHA-256 (type 2)
  records = ["1 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.rsa_server.public_key_openssh)}"]
}
```

## Signature

```hcl
sha256_fingerprint(public_key string) string
```

## Arguments

- `public_key` (String) SSH public key in OpenSSH format

## Return Value

Returns the SHA-256 fingerprint as a 64-character hexadecimal string.

## Algorithm Numbers

When constructing SSHFP records, use these algorithm numbers:

- **1**: RSA
- **2**: DSA  
- **3**: ECDSA
- **4**: Ed25519

## Note

This function requires Terraform 1.8.0 or later. For earlier versions, use the `sshfp_fingerprint` data source instead.