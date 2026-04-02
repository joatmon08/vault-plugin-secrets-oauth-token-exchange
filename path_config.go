package oauth

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// oauthConfig includes the configuration required to instantiate
// a new OAuth client for token exchange
type oauthConfig struct {
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

// pathConfig extends the Vault API with a `/config` endpoint for the backend
func pathConfig(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"client_id": {
					Type:        framework.TypeString,
					Description: "OAuth 2.0 Client ID for OIDC provider",
					Required:    true,
				},
				"client_secret": {
					Type:        framework.TypeString,
					Description: "OAuth 2.0 Client Secret for OIDC provider",
					Required:    true,
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"userinfo_endpoint": {
					Type:        framework.TypeString,
					Description: "OIDC userinfo endpoint URL for verifying subject tokens",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
					Summary:  "Read the OAuth provider configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Configure the OAuth provider settings",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Summary:  "Update the OAuth provider settings",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
					Summary:  "Delete the OAuth provider configuration",
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathConfigHelpSynopsis,
			HelpDescription: pathConfigHelpDescription,
		},
	}
}

// pathConfigExistenceCheck verifies if the configuration exists
func (b *oauthBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

// pathConfigRead reads the OAuth configuration
func (b *oauthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"client_id":          config.ClientID,
			"userinfo_endpoint":  config.UserinfoEndpoint,
		},
	}, nil
}

// pathConfigWrite writes the OAuth configuration
func (b *oauthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientID := data.Get("client_id").(string)
	clientSecret := data.Get("client_secret").(string)
	userinfoEndpoint := data.Get("userinfo_endpoint").(string)

	// Validate required fields
	if clientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}
	if clientSecret == "" {
		return logical.ErrorResponse("client_secret is required"), nil
	}
	if userinfoEndpoint == "" {
		return logical.ErrorResponse("userinfo_endpoint is required"), nil
	}

	config := &oauthConfig{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		UserinfoEndpoint: userinfoEndpoint,
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset the client so it gets recreated with new config
	b.reset()

	return &logical.Response{
		Data: map[string]interface{}{
			"userinfo_endpoint": userinfoEndpoint,
		},
	}, nil
}

// pathConfigDelete deletes the OAuth configuration
func (b *oauthBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

// getConfig retrieves the OAuth configuration from storage
func getConfig(ctx context.Context, s logical.Storage) (*oauthConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(oauthConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading configuration: %w", err)
	}

	return config, nil
}

const pathConfigHelpSynopsis = `Configure the OAuth 2.0 provider for token exchange.`

const pathConfigHelpDescription = `
The OAuth Token Exchange backend requires configuration of an OAuth 2.0 / OIDC provider.
You need to provide:
- client_id: The OAuth 2.0 client ID
- client_secret: The OAuth 2.0 client secret
- userinfo_endpoint: The OIDC userinfo endpoint URL

The userinfo_endpoint is used to verify subject tokens during the token exchange process.
This secrets engine itself acts as the RFC 8693 token exchange endpoint.
`

// Made with Bob
