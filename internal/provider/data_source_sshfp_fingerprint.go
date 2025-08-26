package provider

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
)

var _ datasource.DataSource = &SSHFPFingerprintDataSource{}

func NewSSHFPFingerprintDataSource() datasource.DataSource {
	return &SSHFPFingerprintDataSource{}
}

type SSHFPFingerprintDataSource struct{}

type SSHFPFingerprintDataSourceModel struct {
	PublicKey       types.String `tfsdk:"public_key"`
	FingerprintType types.Int64  `tfsdk:"fingerprint_type"`
	Algorithm       types.Int64  `tfsdk:"algorithm"`
	AlgorithmName   types.String `tfsdk:"algorithm_name"`
	Fingerprint     types.String `tfsdk:"fingerprint"`
	Record          types.String `tfsdk:"record"`
}

func (d *SSHFPFingerprintDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fingerprint"
}

func (d *SSHFPFingerprintDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Generate SSHFP DNS record components from an SSH public key",

		Attributes: map[string]schema.Attribute{
			"public_key": schema.StringAttribute{
				MarkdownDescription: "SSH public key in OpenSSH format",
				Required:            true,
			},
			"fingerprint_type": schema.Int64Attribute{
				MarkdownDescription: "Fingerprint type: 1 (SHA-1) or 2 (SHA-256). Defaults to 2.",
				Optional:            true,
			},
			"algorithm": schema.Int64Attribute{
				MarkdownDescription: "SSH algorithm number: 1 (RSA), 2 (DSA), 3 (ECDSA), 4 (Ed25519)",
				Computed:            true,
			},
			"algorithm_name": schema.StringAttribute{
				MarkdownDescription: "Human-readable algorithm name",
				Computed:            true,
			},
			"fingerprint": schema.StringAttribute{
				MarkdownDescription: "The fingerprint as a hex string",
				Computed:            true,
			},
			"record": schema.StringAttribute{
				MarkdownDescription: "Complete SSHFP record value in format: algorithm type fingerprint",
				Computed:            true,
			},
		},
	}
}

func (d *SSHFPFingerprintDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SSHFPFingerprintDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Default fingerprint type to SHA-256 if not specified
	fingerprintType := int64(2)
	if !data.FingerprintType.IsNull() {
		fingerprintType = data.FingerprintType.ValueInt64()
	}

	// Validate fingerprint type
	if fingerprintType != 1 && fingerprintType != 2 {
		resp.Diagnostics.AddError(
			"Invalid Fingerprint Type",
			fmt.Sprintf("Fingerprint type must be 1 (SHA-1) or 2 (SHA-256), got %d", fingerprintType),
		)
		return
	}

	// Ensure the public key string ends with a newline (required by ParseAuthorizedKey)
	publicKeyStr := strings.TrimSpace(data.PublicKey.ValueString()) + "\n"

	// Parse the SSH public key
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyStr))
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Parse SSH Public Key",
			fmt.Sprintf("Unable to parse the provided SSH public key: %s", err.Error()),
		)
		return
	}

	// Determine the algorithm number and name based on key type
	algorithm, algorithmName, err := getAlgorithmDetails(publicKey.Type())
	if err != nil {
		resp.Diagnostics.AddError(
			"Unsupported Key Type",
			err.Error(),
		)
		return
	}

	// Get the raw key material
	keyBytes := publicKey.Marshal()

	// Calculate fingerprint based on type
	var fingerprint string
	if fingerprintType == 1 {
		// SHA-1
		hash := sha1.Sum(keyBytes)
		fingerprint = hex.EncodeToString(hash[:])
	} else {
		// SHA-256
		hash := sha256.Sum256(keyBytes)
		fingerprint = hex.EncodeToString(hash[:])
	}

	// Generate the complete SSHFP record value
	record := fmt.Sprintf("%d %d %s", algorithm, fingerprintType, fingerprint)

	// Set computed attributes
	data.FingerprintType = types.Int64Value(fingerprintType)
	data.Algorithm = types.Int64Value(int64(algorithm))
	data.AlgorithmName = types.StringValue(algorithmName)
	data.Fingerprint = types.StringValue(fingerprint)
	data.Record = types.StringValue(record)

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func getAlgorithmDetails(keyType string) (int, string, error) {
	switch keyType {
	case "ssh-rsa":
		return 1, "RSA", nil
	case "ssh-dss":
		return 2, "DSA", nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return 3, "ECDSA", nil
	case "ssh-ed25519":
		return 4, "Ed25519", nil
	default:
		return 0, "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}