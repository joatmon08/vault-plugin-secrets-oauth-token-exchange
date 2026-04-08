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
	ClientID                   string `json:"client_id"`
	ClientSecret               string `json:"client_secret"`
	SubjectTokenJWKSURI        string `json:"subject_token_jwks_uri"`
	IdentitySecretsEnginePath  string `json:"identity_secrets_engine_path"`
	VaultAddr                  string `json:"vault_addr"`
	VaultNamespace             string `json:"vault_namespace"`
	VaultToken                 string `json:"vault_token"`
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
				"subject_token_jwks_uri": {
					Type:        framework.TypeString,
					Description: "JWKS URI for verifying subject tokens (e.g., https://issuer/.well-known/jwks.json)",
				},
				"identity_secrets_engine_path": {
					Type:        framework.TypeString,
					Description: "Path to Vault identity secrets engine for actor_token (default: 'identity')",
					Default:     "identity",
				},
				"vault_addr": {
					Type:        framework.TypeString,
					Description: "Vault address for retrieving actor tokens from identity secrets engine",
				},
				"vault_namespace": {
					Type:        framework.TypeString,
					Description: "Vault namespace for retrieving actor tokens (Vault Enterprise only)",
				},
				"vault_token": {
					Type:        framework.TypeString,
					Description: "Vault token with access to the identity secrets engine for retrieving actor tokens",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
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

	respData := map[string]interface{}{
		"client_id": config.ClientID,
	}
	
	if config.SubjectTokenJWKSURI != "" {
		respData["subject_token_jwks_uri"] = config.SubjectTokenJWKSURI
	}
	if config.IdentitySecretsEnginePath != "" {
		respData["identity_secrets_engine_path"] = config.IdentitySecretsEnginePath
	}
	if config.VaultAddr != "" {
		respData["vault_addr"] = config.VaultAddr
	}
	if config.VaultNamespace != "" {
		respData["vault_namespace"] = config.VaultNamespace
	}
	if config.VaultToken != "" {
		respData["vault_token_set"] = true
	}
	
	return &logical.Response{
		Data: respData,
	}, nil
}

// pathConfigWrite writes the OAuth configuration
func (b *oauthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientID := data.Get("client_id").(string)
	clientSecret := data.Get("client_secret").(string)

	// Validate required fields
	if clientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}
	if clientSecret == "" {
		return logical.ErrorResponse("client_secret is required"), nil
	}

	config := &oauthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	
	if jwksURI, ok := data.GetOk("subject_token_jwks_uri"); ok {
		config.SubjectTokenJWKSURI = jwksURI.(string)
	}
	
	// Set identity_secrets_engine_path with default value
	if identityPath, ok := data.GetOk("identity_secrets_engine_path"); ok {
		config.IdentitySecretsEnginePath = identityPath.(string)
	} else {
		config.IdentitySecretsEnginePath = "identity"
	}
	
	if vaultAddr, ok := data.GetOk("vault_addr"); ok {
		config.VaultAddr = vaultAddr.(string)
	}
	if vaultNamespace, ok := data.GetOk("vault_namespace"); ok {
		config.VaultNamespace = vaultNamespace.(string)
	}
	if vaultToken, ok := data.GetOk("vault_token"); ok {
		config.VaultToken = vaultToken.(string)
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

	return nil, nil
}

// pathConfigDelete deletes the OAuth configuration
func (b *oauthBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}

	b.reset()

	return &logical.Response{
		Data: map[string]interface{}{
			"client_id": data.Get("client_id").(string),
		},
	}, nil
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

Optional configuration for subject token verification:
- subject_token_jwks_uri: JWKS URI for verifying subject token signatures

Optional Vault configuration for actor token verification:
- identity_secrets_engine_path: Path to Vault identity secrets engine (default: 'identity')
- vault_addr: Vault address for retrieving actor tokens
- vault_namespace: Vault namespace (Vault Enterprise only)
- vault_token: Vault token with access to the identity secrets engine

Subject tokens are verified by validating the JWT signature against the JWKS URI if provided,
or by decoding and validating the JWT claims if no JWKS URI is configured.
This secrets engine itself acts as the RFC 8693 token exchange endpoint.
`

// Made with Bob
