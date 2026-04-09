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
	Name              string        `json:"name"`
	Key               string        `json:"key"`
	Issuer            string        `json:"issuer"`
	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	ActorTokenJWKSURI string        `json:"actor_token_jwks_uri"`
}

// toResponseData returns response data for a role
func (r *roleEntry) toResponseData() map[string]interface{} {
	data := map[string]interface{}{
		"name":    r.Name,
		"key":     r.Key,
		"issuer":  r.Issuer,
		"ttl":     int64(r.TTL.Seconds()),
		"max_ttl": int64(r.MaxTTL.Seconds()),
	}
	if r.ActorTokenJWKSURI != "" {
		data["actor_token_jwks_uri"] = r.ActorTokenJWKSURI
	}
	return data
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
				"key": {
					Type:        framework.TypeString,
					Description: "Name of the signing key to use for this role",
					Required:    true,
				},
				"issuer": {
					Type:        framework.TypeString,
					Description: "Issuer (iss) claim for tokens issued by this role",
					Required:    true,
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
				"actor_token_jwks_uri": {
					Type:        framework.TypeString,
					Description: "JWKS URI for verifying actor tokens (e.g., https://vault-addr/v1/identity/oidc/.well-known/keys)",
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

	keyName := data.Get("key").(string)
	if keyName == "" {
		return logical.ErrorResponse("missing key name"), nil
	}

	issuer := data.Get("issuer").(string)
	if issuer == "" {
		return logical.ErrorResponse("missing issuer"), nil
	}

	// Verify the key exists
	keyEntry, err := req.Storage.Get(ctx, keyStoragePath+keyName)
	if err != nil {
		return nil, err
	}
	if keyEntry == nil {
		return logical.ErrorResponse("key %q does not exist", keyName), nil
	}

	role := &roleEntry{
		Name:   roleName,
		Key:    keyName,
		Issuer: issuer,
		TTL:    time.Duration(data.Get("ttl").(int)) * time.Second,
		MaxTTL: time.Duration(data.Get("max_ttl").(int)) * time.Second,
	}

	if actorJWKSURI, ok := data.GetOk("actor_token_jwks_uri"); ok {
		role.ActorTokenJWKSURI = actorJWKSURI.(string)
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
Roles define TTL settings for tokens issued during the exchange process.

Clients provide audience, resource, and scope parameters per-request when exchanging tokens.
`

const pathRoleListHelpSynopsis = `List all configured roles.`

const pathRoleListHelpDescription = `This endpoint lists all roles configured for token exchange.`

// Made with Bob
