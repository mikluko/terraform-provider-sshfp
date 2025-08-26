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
	PublicKey     types.String `tfsdk:"public_key"`
	Algorithm     types.Int64  `tfsdk:"algorithm"`
	AlgorithmName types.String `tfsdk:"algorithm_name"`
	SHA1          types.String `tfsdk:"sha1"`
	SHA256        types.String `tfsdk:"sha256"`
	RecordSHA1    types.String `tfsdk:"record_sha1"`
	RecordSHA256  types.String `tfsdk:"record_sha256"`
}

func (d *SSHFPFingerprintDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fingerprint"
}

func (d *SSHFPFingerprintDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Generate SSHFP DNS record components from an SSH public key. This data source automatically generates both SHA-1 and SHA-256 fingerprints.",

		Attributes: map[string]schema.Attribute{
			"public_key": schema.StringAttribute{
				MarkdownDescription: "SSH public key in OpenSSH format",
				Required:            true,
			},
			"algorithm": schema.Int64Attribute{
				MarkdownDescription: "SSH algorithm number: 1 (RSA), 2 (DSA), 3 (ECDSA), 4 (Ed25519)",
				Computed:            true,
			},
			"algorithm_name": schema.StringAttribute{
				MarkdownDescription: "Human-readable algorithm name",
				Computed:            true,
			},
			"sha1": schema.StringAttribute{
				MarkdownDescription: "The SHA-1 fingerprint as a hex string (40 characters)",
				Computed:            true,
			},
			"sha256": schema.StringAttribute{
				MarkdownDescription: "The SHA-256 fingerprint as a hex string (64 characters)",
				Computed:            true,
			},
			"record_sha1": schema.StringAttribute{
				MarkdownDescription: "Complete SSHFP record value with SHA-1: algorithm 1 fingerprint",
				Computed:            true,
			},
			"record_sha256": schema.StringAttribute{
				MarkdownDescription: "Complete SSHFP record value with SHA-256: algorithm 2 fingerprint",
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

	// Calculate SHA-1 fingerprint
	sha1Hash := sha1.Sum(keyBytes)
	fingerprintSHA1 := hex.EncodeToString(sha1Hash[:])

	// Calculate SHA-256 fingerprint
	sha256Hash := sha256.Sum256(keyBytes)
	fingerprintSHA256 := hex.EncodeToString(sha256Hash[:])

	// Generate the complete SSHFP record values
	recordSHA1 := fmt.Sprintf("%d 1 %s", algorithm, fingerprintSHA1)
	recordSHA256 := fmt.Sprintf("%d 2 %s", algorithm, fingerprintSHA256)

	// Set computed attributes
	data.Algorithm = types.Int64Value(int64(algorithm))
	data.AlgorithmName = types.StringValue(algorithmName)
	data.SHA1 = types.StringValue(fingerprintSHA1)
	data.SHA256 = types.StringValue(fingerprintSHA256)
	data.RecordSHA1 = types.StringValue(recordSHA1)
	data.RecordSHA256 = types.StringValue(recordSHA256)

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