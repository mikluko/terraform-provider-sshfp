# Terraform Provider SSHFP

This Terraform provider enables generation and management of SSHFP (SSH Fingerprint) DNS records. It provides both functions and data sources to generate SSHFP fingerprints from SSH public keys for use with any DNS provider.

## Features

- **Data Source** to generate SSHFP record components (works with any Terraform version)
- **Provider Functions** to generate fingerprint hex strings (Terraform 1.8+)
- Support for all SSH key algorithms: RSA, DSA, ECDSA, Ed25519
- SHA-1 and SHA-256 fingerprint generation
- Works with any DNS provider (Route53, Cloudflare, etc.)

## Requirements

- Terraform >= 1.8.0 (for provider functions support)
- Go >= 1.21 (for development)

## Usage

### Data Source (Recommended - works with any Terraform version)

The data source provides full flexibility with separate attributes for each component:

```hcl
terraform {
  required_providers {
    sshfp = {
      source  = "mikluko/sshfp"
      version = "~> 1.0"
    }
  }
}

resource "tls_private_key" "server" {
  algorithm = "ED25519"
}

# Generate SSHFP fingerprint components
data "sshfp_fingerprint" "server" {
  public_key       = tls_private_key.server.public_key_openssh
  fingerprint_type = 2  # SHA-256 (optional, defaults to 2)
}

# Use with AWS Route53 (needs full record string)
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
```

### Provider Functions (Terraform 1.8+ only)

Functions return just the fingerprint hex string, allowing you to construct records as needed:

```hcl
# Manually construct SSHFP record with Ed25519 (algorithm 4) and SHA-256 (type 2)
resource "aws_route53_record" "sshfp" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  records = ["4 2 ${provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)}"]
}
```

## Available Components

### Data Source Attributes

The `sshfp_fingerprint` data source provides:

- `algorithm` - Algorithm number (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519)
- `algorithm_name` - Human-readable algorithm name
- `fingerprint_type` - Fingerprint type (1=SHA-1, 2=SHA-256)
- `fingerprint` - The fingerprint as a hex string
- `record` - Complete SSHFP record value ("algorithm type fingerprint")

### Functions

#### `sha256_fingerprint(public_key)`

Returns the SHA-256 fingerprint hex string only.

**Example:**
```hcl
provider::sshfp::sha256_fingerprint("ssh-ed25519 AAAAC3NzaC1...")
# Returns: "a1b2c3d4..." (just the fingerprint)
```

#### `sha1_fingerprint(public_key)`

Returns the SHA-1 fingerprint hex string only.

**Example:**
```hcl
provider::sshfp::sha1_fingerprint("ssh-rsa AAAAB3NzaC1...")
# Returns: "0123456789abcdef..." (just the fingerprint)
```

### Algorithm Numbers

The provider automatically detects the SSH key type and uses the appropriate algorithm number:

- **1**: RSA
- **2**: DSA  
- **3**: ECDSA
- **4**: Ed25519

### Fingerprint Types

- **1**: SHA-1 (40 hex characters)
- **2**: SHA-256 (64 hex characters)

## Examples

### Multiple Fingerprints

For maximum compatibility, you can provide both SHA-1 and SHA-256 fingerprints:

```hcl
resource "aws_route53_record" "sshfp_both" {
  zone_id = var.zone_id
  name    = "server.example.com"
  type    = "SSHFP"
  ttl     = 300
  
  records = [
    provider::sshfp::sha1_fingerprint(tls_private_key.server.public_key_openssh),
    provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh)
  ]
}
```

### With Cloudflare

```hcl
resource "cloudflare_record" "sshfp" {
  zone_id = var.cloudflare_zone_id
  name    = "server"
  type    = "SSHFP"
  ttl     = 300
  
  data {
    algorithm     = 4  # Ed25519
    type          = 2  # SHA-256
    fingerprint   = trimprefix(
      provider::sshfp::sha256_fingerprint(tls_private_key.server.public_key_openssh),
      "4 2 "
    )
  }
}
```

## Development

### Building the Provider

```bash
go build -o terraform-provider-sshfp
```

### Testing

```bash
go test -v ./...
```

### Installing Locally

```bash
go install .
```

### Release Process

1. **Update documentation**
   ```bash
   go tool tfplugindocs generate
   ```

2. **Commit and push changes**
   ```bash
   git add -A
   git commit -m "Release vX.Y.Z"
   git push origin main
   ```

3. **Create and push annotated tag**
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

4. **Run GoReleaser**
   ```bash
   export GITHUB_TOKEN=...
   export PGP_FINGERPRINT=...
   goreleaser release --clean
   ```

The release will be automatically published to GitHub with all platform binaries, checksums, and signatures.

## License

This provider is distributed under the MIT License.