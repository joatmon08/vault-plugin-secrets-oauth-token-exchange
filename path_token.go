package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// Token type constants as defined in RFC 8693
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

type subjectTokenClaims struct {
	MayAct []*mayActClaim `json:"may_act"`
	jwt.Claims
}

type mayActClaim struct {
	ClientID string `json:"client_id"`
	Subject  string `json:"sub"`
}

type actorTokenClaims struct {
	ClientID string                 `json:"client_id"`
	Subject  string                 `json:"sub"`
	Actors   map[string]interface{} `json:"act"`
}

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
					Description: "OAuth 2.0 client ID that requests the token",
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
	exchangedToken, err := b.performTokenExchange(ctx, req, config, role, subjectToken, actorToken, grantType, clientID, audience, scope)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	return &logical.Response{
		Data: exchangedToken,
	}, nil
}

// accessToken represents the claims for an RFC 8693 access token
type accessToken struct {
	Issuer   string                 `json:"iss"`
	Subject  string                 `json:"sub"`
	Audience string                 `json:"aud"`
	Expiry   int64                  `json:"exp"`
	IssuedAt int64                  `json:"iat"`
	ClientID string                 `json:"client_id"`
	Actors   map[string]interface{} `json:"act"`
	Scope    string                 `json:"scope"`
}

// generatePayload creates the JWT payload from the access token claims
func (t *accessToken) generatePayload() ([]byte, error) {
	output := map[string]interface{}{
		"iss":       t.Issuer,
		"sub":       t.Subject,
		"aud":       t.Audience,
		"exp":       t.Expiry,
		"iat":       t.IssuedAt,
		"client_id": t.ClientID,
		"act":       t.Actors,
		"scope":     t.Scope,
	}

	return json.Marshal(output)
}

// signPayload signs the payload using the named key's signing key
func (k *namedKey) signPayload(payload []byte) (string, error) {
	if k.SigningKey == nil {
		return "", fmt.Errorf("signing key is nil; rotate the key and try again")
	}

	signingKey := jose.SigningKey{
		Key:       k.SigningKey.Key,
		Algorithm: jose.SignatureAlgorithm(k.Algorithm),
	}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	signedToken, err := signature.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize signature: %w", err)
	}

	return signedToken, nil
}

// performTokenExchange executes the RFC 8693 token exchange
// This secrets engine itself acts as the token exchange endpoint
func (b *oauthBackend) performTokenExchange(ctx context.Context, req *logical.Request, config *oauthConfig, role *roleEntry, subjectToken, actorToken, grantType, clientID, audience, scope string) (map[string]interface{}, error) {
	// Verify subject token
	subjectTokenClaims, err := b.verifySubjectToken(ctx, config, subjectToken)
	if err != nil {
		return nil, fmt.Errorf("subject token verification failed: %w", err)
	}

	// Decode actor token
	actorTokenClaims, err := b.decodeActorToken(actorToken)
	if err != nil {
		return nil, fmt.Errorf("actor token decoding failed: %w", err)
	}

	// Verify top-level actor has permission to act on behalf of subject
	var hasPermission bool
	subjectTokenMayActClaims := subjectTokenClaims.MayAct
	for _, claim := range subjectTokenMayActClaims {
		if claim.ClientID == actorTokenClaims.ClientID && claim.Subject == actorTokenClaims.Subject {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		return nil, fmt.Errorf("actor token does not have permission to act on behalf of subject token")
	}

	// Load the signing key referenced by the role
	key, err := b.getNamedKey(ctx, req.Storage, role.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %q: %w", role.Key, err)
	}
	if key == nil {
		return nil, fmt.Errorf("key %q not found", role.Key)
	}

	// Validate that the actor's client_id is allowed by the key
	if !strListContains(key.AllowedClientIDs, "*") && !strListContains(key.AllowedClientIDs, clientID) {
		return nil, fmt.Errorf("the key %q does not list the client ID %q as an allowed client ID", role.Key, clientID)
	}

	// Calculate token expiry - use role TTL but cap at key verification TTL
	expiry := role.TTL
	if expiry > key.VerificationTTL {
		expiry = key.VerificationTTL
	}

	// Generate the access token
	now := time.Now()
	token := &accessToken{
		Issuer:   role.Issuer,
		Subject:  actorTokenClaims.Subject,
		Audience: audience,
		Expiry:   now.Add(expiry).Unix(),
		IssuedAt: now.Unix(),
		ClientID: clientID,
		Actors: map[string]interface{}{
			"sub":       actorTokenClaims.Subject,
			"client_id": actorTokenClaims.ClientID,
			"act":       actorTokenClaims.Actors,
		},
		Scope: scope,
	}

	// Generate and sign the payload
	payload, err := token.generatePayload()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token payload: %w", err)
	}

	signedToken, err := key.signPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Build the token response according to RFC 8693
	tokenResponse := map[string]interface{}{
		"access_token":      signedToken,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"grant_type":        grantType,
		"expires_in":        int64(expiry.Seconds()),
	}

	return tokenResponse, nil
}

func decodeToken(token string) (map[string]interface{}, error) {
	// Parse the JWT using go-jose (following Vault's pattern)
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// First, extract and validate standard claims
	var standardClaims jwt.Claims
	if err := parsedToken.UnsafeClaimsWithoutVerification(&standardClaims); err != nil {
		return nil, fmt.Errorf("failed to extract JWT claims: %w", err)
	}

	// Use go-jose's built-in validation for standard claims (exp, nbf, iat)
	// This automatically checks token expiry
	expected := jwt.Expected{
		Time: time.Now(),
	}

	if err := standardClaims.Validate(expected); err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	// After validation passes, extract all claims including custom ones
	var allClaims map[string]interface{}
	if err := parsedToken.UnsafeClaimsWithoutVerification(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to extract all JWT claims: %w", err)
	}

	// Verify required claims are present
	if _, ok := allClaims["iss"]; !ok {
		return nil, fmt.Errorf("JWT missing required 'iss' claim")
	}

	if _, ok := allClaims["sub"]; !ok {
		return nil, fmt.Errorf("JWT missing required 'sub' claim")
	}

	if _, ok := allClaims["client_id"]; !ok {
		return nil, fmt.Errorf("JWT missing required 'client_id' claim")
	}

	if _, ok := allClaims["aud"]; !ok {
		return nil, fmt.Errorf("JWT missing required 'aud' claim")
	}

	return allClaims, nil
}

func (b *oauthBackend) decodeActorToken(token string) (*actorTokenClaims, error) {
	claims, err := decodeToken(token)
	if err != nil {
		return nil, err
	}

	clientID, _ := claims["client_id"]
	subject, _ := claims["sub"]

	claim := &actorTokenClaims{
		Subject:  subject.(string),
		ClientID: clientID.(string),
	}

	if actors, ok := claims["act"]; ok {
		claim.Actors = actors.(map[string]interface{})
	}

	return claim, nil
}

// verifySubjectToken verifies the subject token by decoding the JWT
func (b *oauthBackend) verifySubjectToken(ctx context.Context, config *oauthConfig, token string) (*subjectTokenClaims, error) {
	claims, err := decodeToken(token)
	if err != nil {
		return nil, err
	}

	mayActRaw, ok := claims["may_act"]
	if !ok {
		return nil, fmt.Errorf("JWT missing required 'may_act' claim")
	}

	// Handle may_act as an array of maps (comes from JSON as []interface{})
	mayActArray, ok := mayActRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("JWT missing required 'may_act' claim")
	}

	var mayActClaims []*mayActClaim

	for _, item := range mayActArray {
		mayActMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid 'may_act' claim format")
		}

		clientID, hasClientID := mayActMap["client_id"]
		if !hasClientID {
			return nil, fmt.Errorf("JWT missing required 'may_act' claim with 'client_id'")
		}

		sub, hasSub := mayActMap["sub"]
		if !hasSub {
			return nil, fmt.Errorf("JWT missing required 'may_act' claim with 'sub'")
		}

		mayActClaims = append(mayActClaims, &mayActClaim{
			ClientID: clientID.(string),
			Subject:  sub.(string),
		})
	}

	subjectTokenClaims := &subjectTokenClaims{
		MayAct: mayActClaims,
		Claims: jwt.Claims{
			Subject: claims["sub"].(string),
		},
	}

	return subjectTokenClaims, nil
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

// getNamedKey retrieves a named key from storage
func (b *oauthBackend) getNamedKey(ctx context.Context, s logical.Storage, name string) (*namedKey, error) {
	entry, err := s.Get(ctx, keyStoragePath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var key namedKey
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, fmt.Errorf("error reading key: %w", err)
	}

	return &key, nil
}

// strListContains checks if a string list contains a specific string
func strListContains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
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
