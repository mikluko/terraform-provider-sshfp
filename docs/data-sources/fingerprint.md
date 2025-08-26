---
page_title: "sshfp_fingerprint Data Source - terraform-provider-sshfp"
subcategory: ""
description: |-
  Generate SSHFP DNS record components from an SSH public key
---

# sshfp_fingerprint (Data Source)

Generates SSHFP DNS record components from an SSH public key. This data source automatically detects the SSH key algorithm and generates the appropriate fingerprint.

## Example Usage

```terraform
# Basic usage with default SHA-256 fingerprint
data "sshfp_fingerprint" "example" {
  public_key = tls_private_key.server.public_key_openssh
}

# Explicit SHA-1 fingerprint for legacy support
data "sshfp_fingerprint" "legacy" {
  public_key       = tls_private_key.server.public_key_openssh
  fingerprint_type = 1  # SHA-1
}

# Use with AWS Route53 (needs complete record string)
resource "aws_route53_record" "sshfp" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  records = [data.sshfp_fingerprint.example.record]
}

# Use with Cloudflare (needs separate components)
resource "cloudflare_record" "sshfp" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm   = data.sshfp_fingerprint.example.algorithm
    type        = data.sshfp_fingerprint.example.fingerprint_type
    fingerprint = data.sshfp_fingerprint.example.fingerprint
  }
}
```

## Schema

### Required

- `public_key` (String) SSH public key in OpenSSH format

### Optional

- `fingerprint_type` (Number) Fingerprint type: 1 (SHA-1) or 2 (SHA-256). Defaults to 2.

### Read-Only

- `algorithm` (Number) SSH algorithm number: 1 (RSA), 2 (DSA), 3 (ECDSA), 4 (Ed25519)
- `algorithm_name` (String) Human-readable algorithm name
- `fingerprint` (String) The fingerprint as a hex string
- `record` (String) Complete SSHFP record value in format: algorithm type fingerprint

## Algorithm Numbers

The data source automatically detects the SSH key type and sets the appropriate algorithm number:

- **1**: RSA
- **2**: DSA
- **3**: ECDSA
- **4**: Ed25519

## Fingerprint Types

- **1**: SHA-1 (40 hex characters) - Legacy support
- **2**: SHA-256 (64 hex characters) - Recommended