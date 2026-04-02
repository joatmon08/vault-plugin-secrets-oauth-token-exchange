package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleStoragePrefix = "role/"
)

// roleEntry defines the data required for a Vault role to perform token exchange
type roleEntry struct {
	Name                       string        `json:"name"`
	Audience                   string        `json:"audience"`
	Resource                   string        `json:"resource"`
	Scope                      string        `json:"scope"`
	IdentitySecretsEnginePath  string        `json:"identity_secrets_engine_path"`
	VaultAddr                  string        `json:"vault_addr"`
	VaultNamespace             string        `json:"vault_namespace"`
	VaultToken                 string        `json:"vault_token"`
	TTL                        time.Duration `json:"ttl"`
	MaxTTL                     time.Duration `json:"max_ttl"`
}

// toResponseData returns response data for a role
func (r *roleEntry) toResponseData() map[string]interface{} {
	respData := map[string]interface{}{
		"name":    r.Name,
		"ttl":     int64(r.TTL.Seconds()),
		"max_ttl": int64(r.MaxTTL.Seconds()),
	}
	
	if r.Audience != "" {
		respData["audience"] = r.Audience
	}
	if r.Resource != "" {
		respData["resource"] = r.Resource
	}
	if r.Scope != "" {
		respData["scope"] = r.Scope
	}
	if r.IdentitySecretsEnginePath != "" {
		respData["identity_secrets_engine_path"] = r.IdentitySecretsEnginePath
	}
	if r.VaultAddr != "" {
		respData["vault_addr"] = r.VaultAddr
	}
	if r.VaultNamespace != "" {
		respData["vault_namespace"] = r.VaultNamespace
	}
	if r.VaultToken != "" {
		respData["vault_token_set"] = true
	}
	
	return respData
}

// pathRole extends the Vault API with a `/role` endpoint for the backend
func pathRole(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"audience": {
					Type:        framework.TypeString,
					Description: "Audience for the token exchange request",
				},
				"resource": {
					Type:        framework.TypeString,
					Description: "Resource for the token exchange request",
				},
				"scope": {
					Type:        framework.TypeString,
					Description: "Scope for the token exchange request",
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
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default TTL for tokens issued by this role",
					Default:     3600,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum TTL for tokens issued by this role",
					Default:     86400,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					Summary:  "Read a role configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Create a new role",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Update an existing role",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					Summary:  "Delete a role",
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
					Summary:  "List all configured roles",
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRoleExistenceCheck verifies if the role exists
func (b *oauthBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return false, nil
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathRoleRead reads a role from storage
func (b *oauthBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: role.toResponseData(),
	}, nil
}

// pathRoleWrite creates or updates a role
func (b *oauthBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role := &roleEntry{
		Name:   roleName,
		TTL:    time.Duration(data.Get("ttl").(int)) * time.Second,
		MaxTTL: time.Duration(data.Get("max_ttl").(int)) * time.Second,
	}

	if audience, ok := data.GetOk("audience"); ok {
		role.Audience = audience.(string)
	}
	if resource, ok := data.GetOk("resource"); ok {
		role.Resource = resource.(string)
	}
	if scope, ok := data.GetOk("scope"); ok {
		role.Scope = scope.(string)
	}
	
	// Set identity_secrets_engine_path with default value
	if identityPath, ok := data.GetOk("identity_secrets_engine_path"); ok {
		role.IdentitySecretsEnginePath = identityPath.(string)
	} else {
		role.IdentitySecretsEnginePath = "identity"
	}
	
	if vaultAddr, ok := data.GetOk("vault_addr"); ok {
		role.VaultAddr = vaultAddr.(string)
	}
	if vaultNamespace, ok := data.GetOk("vault_namespace"); ok {
		role.VaultNamespace = vaultNamespace.(string)
	}
	if vaultToken, ok := data.GetOk("vault_token"); ok {
		role.VaultToken = vaultToken.(string)
	}

	// Validate TTL values
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON(roleStoragePrefix+roleName, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleDelete deletes a role from storage
func (b *oauthBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	if err := req.Storage.Delete(ctx, roleStoragePrefix+roleName); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleList lists all roles
func (b *oauthBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

// getRole retrieves a role from storage
func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	role := new(roleEntry)
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error reading role: %w", err)
	}

	return role, nil
}

const pathRoleHelpSynopsis = `Manage roles for OAuth 2.0 token exchange.`

const pathRoleHelpDescription = `
This path allows you to create, read, update, and delete roles used for OAuth 2.0 token exchange.
Each role defines optional parameters like audience, resource, and scope as defined in RFC 8693.
The secrets engine will return an OAuth access token.

Roles can also specify identity_secrets_engine_path (default: 'identity') to retrieve actor tokens
from Vault's identity secrets engine, enabling delegation scenarios. When using actor tokens, you
must also provide vault_addr, vault_token, and optionally vault_namespace (for Vault Enterprise)
with permissions to read from the identity secrets engine.
`

const pathRoleListHelpSynopsis = `List all configured roles.`

const pathRoleListHelpDescription = `This endpoint lists all roles configured for token exchange.`

// Made with Bob
