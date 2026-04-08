package oauth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathJWKS extends the Vault API with JWKS endpoint
func pathJWKS(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: `.well-known/keys/?$`,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathJWKSRead,
					Summary:  "Retrieve the public portion of named keys in JWKS format",
				},
			},
			HelpSynopsis:    pathJWKSHelpSynopsis,
			HelpDescription: pathJWKSHelpDescription,
		},
	}
}

// pathJWKSRead returns the public keys in JWKS format
func (b *oauthBackend) pathJWKSRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	jwks, err := b.generatePublicJWKS(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWKS: %w", err)
	}

	responseData, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWKS: %w", err)
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

// generatePublicJWKS generates a JWKS containing all public keys from all named keys
func (b *oauthBackend) generatePublicJWKS(ctx context.Context, s logical.Storage) (*jose.JSONWebKeySet, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	// List all keys
	keyNames, err := s.List(ctx, keyStoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	jwks := &jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0),
	}

	// For each key, add its public keys to the JWKS
	for _, keyName := range keyNames {
		entry, err := s.Get(ctx, keyStoragePath+keyName)
		if err != nil {
			return nil, fmt.Errorf("failed to get key %q: %w", keyName, err)
		}

		if entry == nil {
			continue
		}

		var key namedKey
		if err := entry.DecodeJSON(&key); err != nil {
			return nil, fmt.Errorf("failed to decode key %q: %w", keyName, err)
		}

		// Add current signing key
		if key.SigningKey != nil {
			publicKey := key.SigningKey.Public()
			jwks.Keys = append(jwks.Keys, publicKey)
		}

		// Add next signing key if it exists
		if key.NextSigningKey != nil {
			publicKey := key.NextSigningKey.Public()
			jwks.Keys = append(jwks.Keys, publicKey)
		}

		// Add keys from the key ring (for verification of older tokens)
		for _, expKey := range key.KeyRing {
			// Load the public key from storage
			pubKey, err := loadPublicKey(ctx, s, expKey.KeyID)
			if err != nil {
				// Log but don't fail - key might have been cleaned up
				continue
			}
			if pubKey != nil {
				jwks.Keys = append(jwks.Keys, *pubKey)
			}
		}
	}

	return jwks, nil
}

// loadPublicKey loads a public key by its key ID
func loadPublicKey(ctx context.Context, s logical.Storage, keyID string) (*jose.JSONWebKey, error) {
	entry, err := s.Get(ctx, "public_key/"+keyID)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var jwk jose.JSONWebKey
	if err := entry.DecodeJSON(&jwk); err != nil {
		return nil, err
	}

	return &jwk, nil
}

const pathJWKSHelpSynopsis = `Retrieve public keys in JWKS format`

const pathJWKSHelpDescription = `
This endpoint returns the public portion of all named keys in JSON Web Key Set (JWKS) format.
The JWKS can be used to verify tokens signed by this secrets engine.

The response includes:
- Current signing keys for all named keys
- Next signing keys (if rotation is pending)
- Keys in the key ring (for verifying older tokens within the verification TTL)

This endpoint is typically used by resource servers to verify tokens issued by this
OAuth token exchange endpoint.
`

// Made with Bob
