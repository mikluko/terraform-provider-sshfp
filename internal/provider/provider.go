package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure SSHFPProvider satisfies various provider interfaces.
var _ provider.Provider = &SSHFPProvider{}
var _ provider.ProviderWithFunctions = &SSHFPProvider{}

// SSHFPProvider defines the provider implementation.
type SSHFPProvider struct {
	version string
}

// SSHFPProviderModel describes the provider data model.
type SSHFPProviderModel struct{}

func (p *SSHFPProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sshfp"
	resp.Version = p.version
}

func (p *SSHFPProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}

func (p *SSHFPProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data SSHFPProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}

func (p *SSHFPProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *SSHFPProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSSHFPFingerprintDataSource,
	}
}

func (p *SSHFPProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{
		NewSHA256FingerprintFunction,
		NewSHA1FingerprintFunction,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &SSHFPProvider{
			version: version,
		}
	}
}