---
page_title: "sha1_fingerprint Function - terraform-provider-sshfp"
subcategory: ""
description: |-
  Generate SHA-1 fingerprint from SSH public key
---

# sha1_fingerprint Function

Generates a SHA-1 fingerprint (hex string) from an SSH public key. This function returns only the fingerprint hex string. Note that SHA-256 is recommended for new deployments.

## Example Usage

```terraform
# Generate Ed25519 key
resource "tls_private_key" "server" {
  algorithm = "ED25519"
}

# Get SHA-1 fingerprint
output "fingerprint_sha1" {
  value = provider::sshfp::sha1_fingerprint(tls_private_key.server.public_key_openssh)
}

# Use with Route53 - manually construct SSHFP record
# Format: "algorithm type fingerprint"
resource "aws_route53_record" "sshfp_sha1" {
  zone_id = var.zone_id
  name    = "legacy.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  # Ed25519 (algorithm 4) with SHA-1 (type 1)
  records = ["4 1 ${provider::sshfp::sha1_fingerprint(tls_private_key.server.public_key_openssh)}"]
}

# Both SHA-1 and SHA-256 for compatibility
resource "aws_route53_record" "sshfp_both" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  records = [
    "4 1 ${provider::sshfp::sha1_fingerprint(tls_private_key.server.public_key_openssh)}",
    "4 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)}"
  ]
}
```

## Signature

```hcl
sha1_fingerprint(public_key string) string
```

## Arguments

- `public_key` (String) SSH public key in OpenSSH format

## Return Value

Returns the SHA-1 fingerprint as a 40-character hexadecimal string.

## Algorithm Numbers

When constructing SSHFP records, use these algorithm numbers:

- **1**: RSA
- **2**: DSA
- **3**: ECDSA
- **4**: Ed25519

## Security Note

SHA-1 is considered cryptographically weak. Use SHA-256 (`sha256_fingerprint`) for new deployments. SHA-1 support is provided for legacy compatibility only.

## Note

This function requires Terraform 1.8.0 or later. For earlier versions, use the `sshfp_fingerprint` data source instead.