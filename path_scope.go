// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/identitytpl"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	scopeStoragePrefix = "scope/"
)

// scope defines a scope with a template for populating claims
type scope struct {
	Template    string `json:"template"`
	Description string `json:"description"`
}

// pathScope extends the Vault API with a `/scope` endpoint for the backend
func pathScope(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "scope/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the scope",
					Required:    true,
				},
				"template": {
					Type:        framework.TypeString,
					Description: "The template string to use for the scope. This may be in string-ified JSON or base64 format.",
				},
				"description": {
					Type:        framework.TypeString,
					Description: "The description of the scope",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathScopeRead,
					Summary:  "Read a scope configuration",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathScopeWrite,
					Summary:  "Create a new scope",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathScopeWrite,
					Summary:  "Update an existing scope",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathScopeDelete,
					Summary:  "Delete a scope",
				},
			},
			ExistenceCheck:  b.pathScopeExistenceCheck,
			HelpSynopsis:    pathScopeHelpSynopsis,
			HelpDescription: pathScopeHelpDescription,
		},
		{
			Pattern: "scope/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathScopeList,
					Summary:  "List all configured scopes",
				},
			},
			HelpSynopsis:    pathScopeListHelpSynopsis,
			HelpDescription: pathScopeListHelpDescription,
		},
	}
}

// pathScopeExistenceCheck verifies if the scope exists
func (b *oauthBackend) pathScopeExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	scopeName := data.Get("name").(string)
	if scopeName == "" {
		return false, nil
	}

	scope, err := getScope(ctx, req.Storage, scopeName)
	if err != nil {
		return false, err
	}

	return scope != nil, nil
}

// pathScopeRead reads a scope from storage
func (b *oauthBackend) pathScopeRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	scopeName := data.Get("name").(string)
	if scopeName == "" {
		return logical.ErrorResponse("missing scope name"), nil
	}

	scope, err := getScope(ctx, req.Storage, scopeName)
	if err != nil {
		return nil, err
	}

	if scope == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"template":    scope.Template,
			"description": scope.Description,
		},
	}, nil
}

// pathScopeWrite creates or updates a scope
func (b *oauthBackend) pathScopeWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	scopeName := data.Get("name").(string)
	if scopeName == "" {
		return logical.ErrorResponse("missing scope name"), nil
	}

	var scope scope
	if req.Operation == logical.UpdateOperation {
		entry, err := req.Storage.Get(ctx, scopeStoragePrefix+scopeName)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&scope); err != nil {
				return nil, err
			}
		}
	}

	if descriptionRaw, ok := data.GetOk("description"); ok {
		scope.Description = descriptionRaw.(string)
	} else if req.Operation == logical.CreateOperation {
		scope.Description = data.Get("description").(string)
	}

	if templateRaw, ok := data.GetOk("template"); ok {
		scope.Template = templateRaw.(string)
	} else if req.Operation == logical.CreateOperation {
		scope.Template = data.Get("template").(string)
	}

	// Attempt to decode as base64 and use that if it works
	if decoded, err := base64.StdEncoding.DecodeString(scope.Template); err == nil {
		scope.Template = string(decoded)
	}

	// Validate that template can be parsed and results in valid JSON
	if scope.Template != "" {
		_, populatedTemplate, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
			Mode:   identitytpl.JSONTemplating,
			String: scope.Template,
			Entity: new(logical.Entity),
			Groups: make([]*logical.Group, 0),
		})
		if err != nil {
			return logical.ErrorResponse("error parsing template: %s", err.Error()), nil
		}

		var tmp map[string]interface{}
		if err := json.Unmarshal([]byte(populatedTemplate), &tmp); err != nil {
			return logical.ErrorResponse("error parsing template JSON: %s", err.Error()), nil
		}

		// Check for reserved claims that shouldn't be in scope templates
		reservedClaims := []string{"iss", "sub", "aud", "exp", "iat", "client_id", "act"}
		for key := range tmp {
			for _, reserved := range reservedClaims {
				if key == reserved {
					return logical.ErrorResponse("top level key %q not allowed. Restricted keys: %v",
						key, reservedClaims), nil
				}
			}
		}
	}

	entry, err := logical.StorageEntryJSON(scopeStoragePrefix+scopeName, scope)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathScopeDelete deletes a scope from storage
func (b *oauthBackend) pathScopeDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	scopeName := data.Get("name").(string)
	if scopeName == "" {
		return logical.ErrorResponse("missing scope name"), nil
	}

	// Check if any roles reference this scope
	roles, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}

	var referencingRoles []string
	for _, roleName := range roles {
		role, err := getRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role != nil {
			for _, s := range role.ScopesSupported {
				if s == scopeName {
					referencingRoles = append(referencingRoles, roleName)
					break
				}
			}
		}
	}

	if len(referencingRoles) > 0 {
		return logical.ErrorResponse("unable to delete scope %q because it is currently referenced by these roles: %v",
			scopeName, referencingRoles), logical.ErrInvalidRequest
	}

	if err := req.Storage.Delete(ctx, scopeStoragePrefix+scopeName); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathScopeList lists all scopes
func (b *oauthBackend) pathScopeList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	scopes, err := req.Storage.List(ctx, scopeStoragePrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(scopes), nil
}

// getScope retrieves a scope from storage
func getScope(ctx context.Context, s logical.Storage, name string) (*scope, error) {
	entry, err := s.Get(ctx, scopeStoragePrefix+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	scope := new(scope)
	if err := entry.DecodeJSON(&scope); err != nil {
		return nil, fmt.Errorf("error reading scope: %w", err)
	}

	return scope, nil
}

const pathScopeHelpSynopsis = `Manage scopes for OAuth 2.0 token exchange.`

const pathScopeHelpDescription = `
This path allows you to create, read, update, and delete scopes used for OAuth 2.0 token exchange.
Scopes define templates that populate additional claims in the exchanged tokens based on entity
and group information.

The template uses the identity templating language to access entity and group metadata.
Templates must produce valid JSON and cannot use reserved claim names (iss, sub, aud, exp, iat, client_id, act).
`

const pathScopeListHelpSynopsis = `List all configured scopes.`

const pathScopeListHelpDescription = `This endpoint lists all scopes configured for token exchange.`

// Made with Bob
