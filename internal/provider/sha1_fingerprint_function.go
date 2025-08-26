package provider

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"golang.org/x/crypto/ssh"
)

var _ function.Function = SHA1FingerprintFunction{}

func NewSHA1FingerprintFunction() function.Function {
	return SHA1FingerprintFunction{}
}

type SHA1FingerprintFunction struct{}

func (r SHA1FingerprintFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "sha1_fingerprint"
}

func (r SHA1FingerprintFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Generate SHA-1 fingerprint from SSH public key",
		MarkdownDescription: "Generates a SHA-1 fingerprint (hex string) from an SSH public key. Note: SHA-256 is recommended for new deployments.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "public_key",
				MarkdownDescription: "SSH public key in OpenSSH format",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r SHA1FingerprintFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var publicKeyStr string

	resp.Error = function.ConcatFuncErrors(req.Arguments.Get(ctx, &publicKeyStr))
	if resp.Error != nil {
		return
	}

	// Ensure the public key string ends with a newline (required by ParseAuthorizedKey)
	publicKeyStr = strings.TrimSpace(publicKeyStr) + "\n"

	// Parse the SSH public key
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err != nil {
		resp.Error = function.NewFuncError(fmt.Sprintf("Failed to parse SSH public key: %s", err.Error()))
		return
	}

	// Get the raw key material
	keyBytes := publicKey.Marshal()

	// Calculate SHA-1 fingerprint
	hash := sha1.Sum(keyBytes)
	fingerprint := hex.EncodeToString(hash[:])

	// Return just the fingerprint hex string
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, fingerprint))
}