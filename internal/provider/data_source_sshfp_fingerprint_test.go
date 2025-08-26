package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSSHFPFingerprintDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSSHFPFingerprintDataSourceConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Ed25519 with SHA-256
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519_sha256", "algorithm", "4"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519_sha256", "algorithm_name", "Ed25519"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519_sha256", "fingerprint_type", "2"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519_sha256", "fingerprint",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519_sha256", "record",
						regexp.MustCompile(`^4 2 [a-f0-9]{64}$`)),

					// Ed25519 with SHA-1
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519_sha1", "algorithm", "4"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519_sha1", "algorithm_name", "Ed25519"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519_sha1", "fingerprint_type", "1"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519_sha1", "fingerprint",
						regexp.MustCompile(`^[a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519_sha1", "record",
						regexp.MustCompile(`^4 1 [a-f0-9]{40}$`)),

					// RSA with default SHA-256
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.rsa_default", "algorithm", "1"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.rsa_default", "algorithm_name", "RSA"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.rsa_default", "fingerprint_type", "2"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.rsa_default", "fingerprint",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.rsa_default", "record",
						regexp.MustCompile(`^1 2 [a-f0-9]{64}$`)),

					// ECDSA
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ecdsa", "algorithm", "3"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ecdsa", "algorithm_name", "ECDSA"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ecdsa", "fingerprint_type", "2"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ecdsa", "fingerprint",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ecdsa", "record",
						regexp.MustCompile(`^3 2 [a-f0-9]{64}$`)),
				),
			},
		},
	})
}

const testAccSSHFPFingerprintDataSourceConfig = `
data "sshfp_fingerprint" "ed25519_sha256" {
  public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHBHmiqmUzZw99i59cin9XMb68mGdUi+91e/RAQt+r0 test"
  fingerprint_type = 2
}

data "sshfp_fingerprint" "ed25519_sha1" {
  public_key       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHBHmiqmUzZw99i59cin9XMb68mGdUi+91e/RAQt+r0 test"
  fingerprint_type = 1
}

data "sshfp_fingerprint" "rsa_default" {
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8cwASB/ave2CqgEblvG374PRhA4WbyOZHg4J3bgQKcqbmFGbN/2lZPda3tqAjulv1SipoNNez6Pb2Rfo9X7I36kTBukRD2y7O4vnbGp0fTamFeM2S9OxI6VjLOkldQV3Quh1D+pb6kmgNwJBhdWsr3LGiongT6hDzRdC1HWwV4i5/IIrZ3DajQ1fw5kU3S6NOu6j+lNLMeMf3x3wWd8jV66gEVhs1vsgZFOYY42wrgcsWc1dj8QfesHPSTR7zCZEuqIV6qI3A5y+vMCORiIx7oKSdWGv7Rfbiotetvu8LswYnxiAbpJg5+9IhIjPtf7gycQTUHAMGSihe//Ym6/oT test"
  # fingerprint_type defaults to 2
}

data "sshfp_fingerprint" "ecdsa" {
  public_key       = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIwuiu43cVadZb6g985aZmEG16AArGiplhbmLrBlRVmTiIl0elNQpAls3ZEujLkRjEdBF5idR7OKtFMZzXQRK/Y= test"
  fingerprint_type = 2
}
`