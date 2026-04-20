// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathOIDCDiscovery(t *testing.T) {
	b, storage := getTestBackend(t)

	t.Run("Discovery without roles", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ".well-known/openid-configuration",
			Storage:   storage,
			Connection: &logical.Connection{
				RemoteAddr: "https://vault.example.com",
			},
			MountPoint: "oauth-token-exchange/",
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		if resp.Data[logical.HTTPStatusCode] != 200 {
			t.Fatalf("expected status 200, got %v", resp.Data[logical.HTTPStatusCode])
		}

		if resp.Data[logical.HTTPContentType] != "application/json" {
			t.Fatalf("expected content type application/json, got %v", resp.Data[logical.HTTPContentType])
		}

		rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
		if !ok {
			t.Fatal("expected raw body to be []byte")
		}

		var discovery oidcDiscoveryResponse
		if err := json.Unmarshal(rawBody, &discovery); err != nil {
			t.Fatalf("failed to unmarshal discovery document: %v", err)
		}

		// Verify required fields
		if discovery.JWKSURI == "" {
			t.Error("expected jwks_uri to be set")
		}

		if discovery.TokenEndpoint == "" {
			t.Error("expected token_endpoint to be set")
		}

		if len(discovery.ResponseTypesSupported) == 0 {
			t.Error("expected response_types_supported to be set")
		}

		if len(discovery.SubjectTypesSupported) == 0 {
			t.Error("expected subject_types_supported to be set")
		}

		if len(discovery.IDTokenSigningAlgValuesSupported) == 0 {
			t.Error("expected id_token_signing_alg_values_supported to be set")
		}

		// Verify grant types include token exchange
		foundTokenExchange := false
		for _, gt := range discovery.GrantTypesSupported {
			if gt == grantTypeTokenExchange {
				foundTokenExchange = true
				break
			}
		}
		if !foundTokenExchange {
			t.Error("expected grant_types_supported to include token-exchange")
		}
	})

	t.Run("Discovery with configured role", func(t *testing.T) {
		// First create a key
		keyReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "key/test-key",
			Storage:   storage,
			Data: map[string]interface{}{
				"rotation_period":    "24h",
				"verification_ttl":   "48h",
				"allowed_algorithms": []string{"RS256"},
			},
		}

		_, err := b.HandleRequest(context.Background(), keyReq)
		if err != nil {
			t.Fatalf("failed to create key: %v", err)
		}

		// Create a role with a custom issuer
		roleReq := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/test-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"key":     "test-key",
				"issuer":  "https://vault.example.com/v1/oauth-token-exchange",
				"ttl":     3600,
				"max_ttl": 86400,
			},
			MountPoint: "oauth-token-exchange/",
		}

		_, err = b.HandleRequest(context.Background(), roleReq)
		if err != nil {
			t.Fatalf("failed to create role: %v", err)
		}

		// Now test the discovery endpoint
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      ".well-known/openid-configuration",
			Storage:   storage,
			Connection: &logical.Connection{
				RemoteAddr: "https://vault.example.com",
			},
			MountPoint: "oauth-token-exchange/",
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
		if !ok {
			t.Fatal("expected raw body to be []byte")
		}

		var discovery oidcDiscoveryResponse
		if err := json.Unmarshal(rawBody, &discovery); err != nil {
			t.Fatalf("failed to unmarshal discovery document: %v", err)
		}

		// Verify issuer matches the role's issuer
		expectedIssuer := "https://vault.example.com/v1/oauth-token-exchange"
		if discovery.Issuer != expectedIssuer {
			t.Errorf("expected issuer %q, got %q", expectedIssuer, discovery.Issuer)
		}

		// Verify JWKS URI is constructed correctly
		expectedJWKSURI := expectedIssuer + "/.well-known/keys"
		if discovery.JWKSURI != expectedJWKSURI {
			t.Errorf("expected jwks_uri %q, got %q", expectedJWKSURI, discovery.JWKSURI)
		}

		// Verify token endpoint is constructed correctly
		expectedTokenEndpoint := expectedIssuer + "/token"
		if discovery.TokenEndpoint != expectedTokenEndpoint {
			t.Errorf("expected token_endpoint %q, got %q", expectedTokenEndpoint, discovery.TokenEndpoint)
		}
	})
}

func TestPathOIDCDiscoveryUnauthenticated(t *testing.T) {
	// Verify the path is in the unauthenticated list by checking the backend structure
	b := backend()

	// Verify the path is in the unauthenticated list
	found := false
	if b.PathsSpecial != nil {
		for _, path := range b.PathsSpecial.Unauthenticated {
			if path == ".well-known/openid-configuration" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("expected .well-known/openid-configuration to be in unauthenticated paths")
	}
}

// Made with Bob