package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

func TestSHA1FingerprintFunction_Known(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test_ed25519" {
					value = provider::sshfp::sha1_fingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHBHmiqmUzZw99i59cin9XMb68mGdUi+91e/RAQt+r0 test")
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchOutput("test_ed25519",
						regexp.MustCompile(`^[a-f0-9]{40}$`)),
				),
			},
			{
				Config: `
				output "test_ecdsa" {
					value = provider::sshfp::sha1_fingerprint("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIwuiu43cVadZb6g985aZmEG16AArGiplhbmLrBlRVmTiIl0elNQpAls3ZEujLkRjEdBF5idR7OKtFMZzXQRK/Y= test")
				}
				`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchOutput("test_ecdsa",
						regexp.MustCompile(`^[a-f0-9]{40}$`)),
				),
			},
		},
	})
}

func TestSHA1FingerprintFunction_Invalid(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_8_0),
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
				output "test" {
					value = provider::sshfp::sha1_fingerprint("not-a-valid-ssh-key")
				}
				`,
				ExpectError: regexp.MustCompile(`Failed to parse\s+SSH public key`),
			},
		},
	})
}