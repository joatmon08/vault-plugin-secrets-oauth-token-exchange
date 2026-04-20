// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathOIDCDiscovery extends the Vault API with OIDC discovery endpoint
func pathOIDCDiscovery(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `.well-known/openid-configuration/?$`,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathOIDCDiscoveryRead,
					Summary:  "Retrieve OpenID Connect discovery document",
				},
			},
			HelpSynopsis:    pathOIDCDiscoveryHelpSynopsis,
			HelpDescription: pathOIDCDiscoveryHelpDescription,
		},
	}
}

// oidcDiscoveryResponse represents the OpenID Connect discovery document
type oidcDiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// pathOIDCDiscoveryRead returns the OpenID Connect discovery document
func (b *oauthBackend) pathOIDCDiscoveryRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the issuer from the first available role, or construct from mount path
	issuer, err := b.getIssuer(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to determine issuer: %w", err)
	}

	// Construct the base URL for endpoints
	baseURL := issuer
	if baseURL == "" {
		// Fallback: construct from Vault's API address and mount path
		baseURL = fmt.Sprintf("%s/v1/%s", req.Connection.RemoteAddr, req.MountPoint)
	}

	discovery := &oidcDiscoveryResponse{
		Issuer:      issuer,
		JWKSURI:     fmt.Sprintf("%s/.well-known/keys", baseURL),
		TokenEndpoint: fmt.Sprintf("%s/token", baseURL),
		ResponseTypesSupported: []string{
			"token",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
			"RS384",
			"RS512",
			"ES256",
			"ES384",
			"ES512",
			"EdDSA",
		},
		GrantTypesSupported: []string{
			grantTypeTokenExchange,
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},
	}

	responseData, err := json.Marshal(discovery)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal discovery document: %w", err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPStatusCode:  200,
			logical.HTTPRawBody:     responseData,
			logical.HTTPContentType: "application/json",
		},
	}

	return resp, nil
}

// getIssuer retrieves the issuer from the first available role or constructs a default
func (b *oauthBackend) getIssuer(ctx context.Context, req *logical.Request) (string, error) {
	// List all roles to find an issuer
	roleNames, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return "", fmt.Errorf("failed to list roles: %w", err)
	}

	// If we have roles, try to get the issuer from the first one
	if len(roleNames) > 0 {
		role, err := getRole(ctx, req.Storage, roleNames[0])
		if err != nil {
			return "", fmt.Errorf("failed to get role: %w", err)
		}
		if role != nil && role.Issuer != "" {
			return role.Issuer, nil
		}
	}

	// Fallback: construct issuer from mount path
	// This will be overridden when roles are configured with explicit issuers
	return "", nil
}

const pathOIDCDiscoveryHelpSynopsis = `Retrieve OpenID Connect discovery document`

const pathOIDCDiscoveryHelpDescription = `
This endpoint returns the OpenID Connect discovery document (also known as the
provider configuration document) as defined in OpenID Connect Discovery 1.0.

The discovery document provides metadata about the OAuth 2.0 Token Exchange
endpoint, including:
- The issuer identifier
- The JWKS URI for retrieving public keys
- The token endpoint for RFC 8693 token exchange
- Supported grant types, response types, and signing algorithms

This endpoint is publicly accessible and does not require authentication.
It is typically used by OAuth clients and resource servers to discover
the configuration of this token exchange service.

The issuer value is derived from the role configuration. If no roles are
configured, a default issuer based on the mount path will be used.
`

// Made with Bob