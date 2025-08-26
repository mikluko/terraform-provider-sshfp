package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"golang.org/x/crypto/ssh"
)

var _ function.Function = SHA256FingerprintFunction{}

func NewSHA256FingerprintFunction() function.Function {
	return SHA256FingerprintFunction{}
}

type SHA256FingerprintFunction struct{}

func (r SHA256FingerprintFunction) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "sha256_fingerprint"
}

func (r SHA256FingerprintFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Generate SHA-256 fingerprint from SSH public key",
		MarkdownDescription: "Generates a SHA-256 fingerprint (hex string) from an SSH public key. Use with algorithm number for complete SSHFP record.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "public_key",
				MarkdownDescription: "SSH public key in OpenSSH format",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r SHA256FingerprintFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
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

	// Calculate SHA-256 fingerprint
	hash := sha256.Sum256(keyBytes)
	fingerprint := hex.EncodeToString(hash[:])

	// Return just the fingerprint hex string
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, fingerprint))
}

func getAlgorithmNumber(keyType string) (int, error) {
	switch keyType {
	case "ssh-rsa":
		return 1, nil
	case "ssh-dss":
		return 2, nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return 3, nil
	case "ssh-ed25519":
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// Helper function to parse OpenSSH format public keys that might be wrapped
func parseOpenSSHKey(publicKeyStr string) (ssh.PublicKey, error) {
	// Try to parse directly first
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err == nil {
		return publicKey, nil
	}

	// If that fails, try to decode base64 if it looks like it might be raw base64
	publicKeyStr = strings.TrimSpace(publicKeyStr)
	if !strings.HasPrefix(publicKeyStr, "ssh-") && !strings.HasPrefix(publicKeyStr, "ecdsa-") {
		// Might be base64 encoded, try to decode
		decoded, err := base64.StdEncoding.DecodeString(publicKeyStr)
		if err == nil {
			publicKey, err := ssh.ParsePublicKey(decoded)
			if err == nil {
				return publicKey, nil
			}
		}
	}

	return nil, fmt.Errorf("unable to parse public key")
}