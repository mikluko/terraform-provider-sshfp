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
					// Ed25519 key tests
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519", "algorithm", "4"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ed25519", "algorithm_name", "Ed25519"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519", "sha1",
						regexp.MustCompile(`^[a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519", "sha256",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519", "record_sha1",
						regexp.MustCompile(`^4 1 [a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ed25519", "record_sha256",
						regexp.MustCompile(`^4 2 [a-f0-9]{64}$`)),

					// RSA key tests
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.rsa", "algorithm", "1"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.rsa", "algorithm_name", "RSA"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.rsa", "sha1",
						regexp.MustCompile(`^[a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.rsa", "sha256",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.rsa", "record_sha1",
						regexp.MustCompile(`^1 1 [a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.rsa", "record_sha256",
						regexp.MustCompile(`^1 2 [a-f0-9]{64}$`)),

					// ECDSA key tests
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ecdsa", "algorithm", "3"),
					resource.TestCheckResourceAttr("data.sshfp_fingerprint.ecdsa", "algorithm_name", "ECDSA"),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ecdsa", "sha1",
						regexp.MustCompile(`^[a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ecdsa", "sha256",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ecdsa", "record_sha1",
						regexp.MustCompile(`^3 1 [a-f0-9]{40}$`)),
					resource.TestMatchResourceAttr("data.sshfp_fingerprint.ecdsa", "record_sha256",
						regexp.MustCompile(`^3 2 [a-f0-9]{64}$`)),
				),
			},
		},
	})
}

const testAccSSHFPFingerprintDataSourceConfig = `
data "sshfp_fingerprint" "ed25519" {
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHBHmiqmUzZw99i59cin9XMb68mGdUi+91e/RAQt+r0 test"
}

data "sshfp_fingerprint" "rsa" {
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8cwASB/ave2CqgEblvG374PRhA4WbyOZHg4J3bgQKcqbmFGbN/2lZPda3tqAjulv1SipoNNez6Pb2Rfo9X7I36kTBukRD2y7O4vnbGp0fTamFeM2S9OxI6VjLOkldQV3Quh1D+pb6kmgNwJBhdWsr3LGiongT6hDzRdC1HWwV4i5/IIrZ3DajQ1fw5kU3S6NOu6j+lNLMeMf3x3wWd8jV66gEVhs1vsgZFOYY42wrgcsWc1dj8QfesHPSTR7zCZEuqIV6qI3A5y+vMCORiIx7oKSdWGv7Rfbiotetvu8LswYnxiAbpJg5+9IhIjPtf7gycQTUHAMGSihe//Ym6/oT test"
}

data "sshfp_fingerprint" "ecdsa" {
  public_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIwuiu43cVadZb6g985aZmEG16AArGiplhbmLrBlRVmTiIl0elNQpAls3ZEujLkRjEdBF5idR7OKtFMZzXQRK/Y= test"
}
`