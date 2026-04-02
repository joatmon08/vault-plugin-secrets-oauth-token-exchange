package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathToken extends the Vault API with token exchange endpoints
func pathToken(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Description: "Name of the role to use for token exchange",
					Required:    true,
				},
				"subject_token": {
					Type:        framework.TypeString,
					Description: "Subject token to be exchanged (obtained externally)",
					Required:    true,
				},
				"actor_token": {
					Type:        framework.TypeString,
					Description: "Optional actor token for delegation scenarios",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathTokenExchange,
					Summary:  "Exchange tokens using RFC 8693",
				},
			},
			HelpSynopsis:    pathTokenHelpSynopsis,
			HelpDescription: pathTokenHelpDescription,
		},
	}
}

// pathTokenExchange performs RFC 8693 token exchange
func (b *oauthBackend) pathTokenExchange(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	subjectToken := data.Get("subject_token").(string)
	if subjectToken == "" {
		return logical.ErrorResponse("missing subject_token"), nil
	}

	// Get the role
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role not found"), nil
	}

	// Get the config
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	if config == nil {
		return logical.ErrorResponse("configuration not found"), nil
	}

	// Get actor token if specified
	var actorToken string
	if actorTokenInput, ok := data.GetOk("actor_token"); ok {
		actorToken = actorTokenInput.(string)
	} else if role.IdentitySecretsEnginePath != "" && role.VaultAddr != "" {
		// Retrieve actor token from Vault identity
		actorToken, err = b.getActorToken(ctx, req, role)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve actor token: %w", err)
		}
	}

	// Perform token exchange
	exchangedToken, err := b.performTokenExchange(ctx, config, role, subjectToken, actorToken)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	return &logical.Response{
		Data: exchangedToken,
	}, nil
}

// performTokenExchange executes the RFC 8693 token exchange
// This secrets engine itself acts as the token exchange endpoint
func (b *oauthBackend) performTokenExchange(ctx context.Context, config *oauthConfig, role *roleEntry, subjectToken, actorToken string) (map[string]interface{}, error) {
	// Verify the subject token against the userinfo endpoint
	if err := b.verifySubjectToken(ctx, config, subjectToken); err != nil {
		return nil, fmt.Errorf("subject token verification failed: %w", err)
	}

	// Build the token response according to RFC 8693
	tokenResponse := map[string]interface{}{
		"access_token":  subjectToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":    "Bearer",
	}

	// Add optional fields if present
	if actorToken != "" {
		tokenResponse["actor_token"] = actorToken
	}
	if role.Audience != "" {
		tokenResponse["audience"] = role.Audience
	}
	if role.Resource != "" {
		tokenResponse["resource"] = role.Resource
	}
	if role.Scope != "" {
		tokenResponse["scope"] = role.Scope
	}

	// Add TTL information
	if role.TTL > 0 {
		tokenResponse["expires_in"] = int64(role.TTL.Seconds())
	}

	return tokenResponse, nil
}

// verifySubjectToken verifies the subject token against the userinfo endpoint
func (b *oauthBackend) verifySubjectToken(ctx context.Context, config *oauthConfig, token string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", config.UserinfoEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call userinfo endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("userinfo endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// getActorToken retrieves an actor token from Vault's identity secrets
func (b *oauthBackend) getActorToken(ctx context.Context, req *logical.Request, role *roleEntry) (string, error) {
	if role.VaultToken == "" {
		return "", fmt.Errorf("vault_token not configured for role %s - required to retrieve actor tokens from identity secrets engine", role.Name)
	}

	if role.VaultAddr == "" {
		return "", fmt.Errorf("vault_addr not configured for role %s - required to retrieve actor tokens from identity secrets engine", role.Name)
	}

	if role.IdentitySecretsEnginePath == "" {
		return "", fmt.Errorf("identity_secrets_engine_path not configured for role %s", role.Name)
	}

	// Create a Vault API client
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = role.VaultAddr
	
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set the token and namespace if provided
	client.SetToken(role.VaultToken)
	if role.VaultNamespace != "" {
		client.SetNamespace(role.VaultNamespace)
	}

	// Read the actor token from the identity secrets engine
	// The path format is typically: identity/oidc/token/<role-name>
	tokenPath := fmt.Sprintf("%s/oidc/token/%s", role.IdentitySecretsEnginePath, role.Name)
	secret, err := client.Logical().Read(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read actor token from %s: %w", tokenPath, err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no data returned from actor token path %s", tokenPath)
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return "", fmt.Errorf("invalid token format from actor token path %s", tokenPath)
	}

	return token, nil
}

const pathTokenHelpSynopsis = `Exchange tokens using RFC 8693 OAuth 2.0 Token Exchange.`

const pathTokenHelpDescription = `
This endpoint performs OAuth 2.0 token exchange according to RFC 8693.
It requires a subject_token (obtained externally from an OIDC provider) and optionally
an actor_token (from Vault's identity secrets) for delegation scenarios.

The subject token is verified against the configured OIDC provider's userinfo endpoint
before performing the token exchange. The endpoint returns an exchanged access token
that can be used with the target resource.
`

// Made with Bob
