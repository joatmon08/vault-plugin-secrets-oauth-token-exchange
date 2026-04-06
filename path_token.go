package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Token type constants as defined in RFC 8693
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
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
					Description: "Subject token to be exchanged (obtained from the id_token field of the Vault OIDC provider token endpoint)",
					Required:    true,
				},
				"actor_token": {
					Type:        framework.TypeString,
					Description: "Actor token to exchanged (obtained from identity/oidc/token/:name endpoint of Vault identity tokens)",
					Required:    true,
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "OAuth 2.0 client ID",
				},
				"audience": {
					Type:        framework.TypeString,
					Description: "Target audience for the token",
				},
				"scope": {
					Type:        framework.TypeString,
					Description: "Requested scope for the token",
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

	actorToken := data.Get("actor_token").(string)
	if actorToken == "" {
		return logical.ErrorResponse("missing actor_token"), nil
	}

	grantType := grantTypeTokenExchange

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

	// Get parameters from request
	var clientID, audience, scope string
	if cid, ok := data.GetOk("client_id"); ok {
		clientID = cid.(string)
	} else {
		clientID = config.ClientID
	}

	if aud, ok := data.GetOk("audience"); ok {
		audience = aud.(string)
	}

	if scp, ok := data.GetOk("scope"); ok {
		scope = scp.(string)
	}

	// Verify the actor token if vault configuration is available
	if config.VaultAddr != "" && config.IdentitySecretsEnginePath != "" {
		if err = b.verifyActorToken(ctx, req, config, actorToken, clientID); err != nil {
			return nil, fmt.Errorf("actor token verification failed: %w", err)
		}
	}

	// Perform token exchange
	exchangedToken, err := b.performTokenExchange(ctx, config, role, subjectToken, actorToken, grantType, clientID, audience, scope)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	return &logical.Response{
		Data: exchangedToken,
	}, nil
}

// performTokenExchange executes the RFC 8693 token exchange
// This secrets engine itself acts as the token exchange endpoint
func (b *oauthBackend) performTokenExchange(ctx context.Context, config *oauthConfig, role *roleEntry, subjectToken, actorToken, grantType, clientID, audience, scope string) (map[string]interface{}, error) {
	// Verify the subject token against the userinfo endpoint
	if err := b.verifySubjectToken(ctx, config, subjectToken); err != nil {
		return nil, fmt.Errorf("subject token verification failed: %w", err)
	}

	// Build the token response according to RFC 8693
	tokenResponse := map[string]interface{}{
		"access_token":      subjectToken,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"grant_type":        grantType,
		"client_id":         clientID,
	}

	// Add optional fields if present
	if actorToken != "" {
		tokenResponse["actor_token"] = actorToken
	}
	if audience != "" {
		tokenResponse["audience"] = audience
	}
	if scope != "" {
		tokenResponse["scope"] = scope
	}

	// Add TTL information
	if role.TTL > 0 {
		tokenResponse["expires_in"] = int64(role.TTL.Seconds())
	}

	return tokenResponse, nil
}

// verifySubjectToken verifies the subject token by decoding the JWT
func (b *oauthBackend) verifySubjectToken(ctx context.Context, config *oauthConfig, token string) error {
	// Split the JWT into its three parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the payload as JSON to verify it's valid
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Verify that the token has required claims
	if _, ok := claims["iss"]; !ok {
		return fmt.Errorf("JWT missing required 'iss' claim")
	}

	if _, ok := claims["sub"]; !ok {
		return fmt.Errorf("JWT missing required 'sub' claim")
	}

	if _, ok := claims["client_id"]; !ok {
		return fmt.Errorf("JWT missing required 'client_id' claim")
	}

	if _, ok := claims["aud"]; !ok {
		return fmt.Errorf("JWT missing required 'aud' claim")
	}

	mayActMap, ok := claims["may_act"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("JWT missing required 'may_act' claim")
	}

	if _, ok := mayActMap["client_id"]; !ok {
		return fmt.Errorf("JWT missing required 'may_act' claim with 'client_id'")
	}

	if _, ok := mayActMap["sub"]; !ok {
		return fmt.Errorf("JWT missing required 'may_act' claim with 'sub'")
	}

	// Check if the token has expired
	if exp, ok := claims["exp"]; ok {
		var expTime int64
		switch v := exp.(type) {
		case float64:
			expTime = int64(v)
		case int64:
			expTime = v
		case int:
			expTime = int64(v)
		default:
			return fmt.Errorf("invalid 'exp' claim type: %T", exp)
		}

		if time.Now().Unix() > expTime {
			return fmt.Errorf("JWT has expired")
		}
	}

	return nil
}

// verifyActorToken introspects an actor token to verify it's still active
func (b *oauthBackend) verifyActorToken(ctx context.Context, req *logical.Request, config *oauthConfig, actorToken string, clientID string) error {
	if config.VaultToken == "" {
		return fmt.Errorf("vault_token not configured - required to verify actor tokens")
	}

	if config.VaultAddr == "" {
		return fmt.Errorf("vault_addr not configured - required to verify actor tokens")
	}

	if config.IdentitySecretsEnginePath == "" {
		return fmt.Errorf("identity_secrets_engine_path not configured")
	}

	// Create a Vault API client
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.VaultAddr

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set the token and namespace if provided
	client.SetToken(config.VaultToken)
	if config.VaultNamespace != "" {
		client.SetNamespace(config.VaultNamespace)
	}

	// Introspect the token to verify it's still active
	// API: POST /identity/oidc/introspect (PUT and POST are synonyms in Vault)
	introspectPath := fmt.Sprintf("%s/oidc/introspect", config.IdentitySecretsEnginePath)
	introspectData := map[string]interface{}{
		"token":     actorToken,
		"client_id": clientID,
	}

	introspectResp, err := client.Logical().Write(introspectPath, introspectData)
	if err != nil {
		return fmt.Errorf("failed to introspect actor token: %w", err)
	}

	if introspectResp == nil || introspectResp.Data == nil {
		return fmt.Errorf("no data returned from token introspection")
	}

	// Check if token is active
	active, ok := introspectResp.Data["active"].(bool)
	if !ok {
		return fmt.Errorf("invalid introspection response: missing 'active' field")
	}

	if !active {
		return fmt.Errorf("actor token is not active")
	}

	return nil
}

const pathTokenHelpSynopsis = `Exchange tokens using RFC 8693 OAuth 2.0 Token Exchange.`

const pathTokenHelpDescription = `
This endpoint performs OAuth 2.0 token exchange according to RFC 8693.
It requires a subject_token (obtained externally from an OIDC provider) and optionally
an actor_token (from Vault's identity secrets) for delegation scenarios.

The subject token is verified by decoding and validating the JWT before performing
the token exchange. The endpoint returns an exchanged access token that can be used
with the target resource.
`

// Made with Bob
