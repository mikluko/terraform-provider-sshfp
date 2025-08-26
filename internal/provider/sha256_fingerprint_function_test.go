package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestSHA256FingerprintFunction_Known(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test_ed25519" {
					value = provider::sshfp::sha256_fingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHBHmiqmUzZw99i59cin9XMb68mGdUi+91e/RAQt+r0 test")
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchOutput("test_ed25519",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
				),
			},
			{
				Config: `
				output "test_rsa" {
					value = provider::sshfp::sha256_fingerprint("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8cwASB/ave2CqgEblvG374PRhA4WbyOZHg4J3bgQKcqbmFGbN/2lZPda3tqAjulv1SipoNNez6Pb2Rfo9X7I36kTBukRD2y7O4vnbGp0fTamFeM2S9OxI6VjLOkldQV3Quh1D+pb6kmgNwJBhdWsr3LGiongT6hDzRdC1HWwV4i5/IIrZ3DajQ1fw5kU3S6NOu6j+lNLMeMf3x3wWd8jV66gEVhs1vsgZFOYY42wrgcsWc1dj8QfesHPSTR7zCZEuqIV6qI3A5y+vMCORiIx7oKSdWGv7Rfbiotetvu8LswYnxiAbpJg5+9IhIjPtf7gycQTUHAMGSihe//Ym6/oT test")
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchOutput("test_rsa",
						regexp.MustCompile(`^[a-f0-9]{64}$`)),
				),
			},
		},
	})
}

func TestSHA256FingerprintFunction_Invalid(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::sshfp::sha256_fingerprint("invalid-key-data")
				}
				`,
				ExpectError: regexp.MustCompile(`Failed to\s+parse SSH public key`),
			},
		},
	})
}