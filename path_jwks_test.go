package oauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathJWKS(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	keyData := map[string]interface{}{
		"name":               "test-key",
		"algorithm":          "RS256",
		"rotation_period":    86400,
		"verification_ttl":   86400,
		"allowed_client_ids": []string{"*"},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data:      keyData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create key: %v", resp.Error())
	}

	// Read the JWKS endpoint
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/keys",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to read JWKS: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.IsError() {
		t.Fatalf("failed to read JWKS: %v", resp.Error())
	}

	// Verify the response structure
	if resp.Data[logical.HTTPStatusCode] != 200 {
		t.Errorf("expected status 200, got %v", resp.Data[logical.HTTPStatusCode])
	}

	if resp.Data[logical.HTTPContentType] != "application/json" {
		t.Errorf("expected content type application/json, got %v", resp.Data[logical.HTTPContentType])
	}

	// Parse the JWKS response
	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatal("expected raw body to be []byte")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}

	// Verify we have at least one key
	if len(jwks.Keys) == 0 {
		t.Error("expected at least one key in JWKS")
	}

	// Verify the key has the expected properties
	key := jwks.Keys[0]
	if key.KeyID == "" {
		t.Error("expected key to have a key ID")
	}
	if key.Algorithm != "RS256" {
		t.Errorf("expected algorithm RS256, got %s", key.Algorithm)
	}
	if key.Use != "sig" {
		t.Errorf("expected use 'sig', got %s", key.Use)
	}
}

func TestPathJWKS_MultipleKeys(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create multiple test keys
	keys := []string{"key1", "key2", "key3"}
	for _, keyName := range keys {
		keyData := map[string]interface{}{
			"name":               keyName,
			"algorithm":          "RS256",
			"rotation_period":    86400,
			"verification_ttl":   86400,
			"allowed_client_ids": []string{"*"},
		}

		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "key/" + keyName,
			Storage:   storage,
			Data:      keyData,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("failed to create key %s: %v", keyName, err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("failed to create key %s: %v", keyName, resp.Error())
		}
	}

	// Read the JWKS endpoint
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/keys",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to read JWKS: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Parse the JWKS response
	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatal("expected raw body to be []byte")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}

	// Verify we have all keys
	if len(jwks.Keys) != len(keys) {
		t.Errorf("expected %d keys in JWKS, got %d", len(keys), len(jwks.Keys))
	}
}

func TestPathJWKS_EmptyWhenNoKeys(t *testing.T) {
	b, storage := getTestBackend(t)

	// Read the JWKS endpoint without creating any keys
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/keys",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to read JWKS: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Parse the JWKS response
	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatal("expected raw body to be []byte")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}

	// Verify we have no keys
	if len(jwks.Keys) != 0 {
		t.Errorf("expected 0 keys in JWKS, got %d", len(jwks.Keys))
	}
}

func TestPathJWKS_AfterKeyRotation(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	keyData := map[string]interface{}{
		"name":               "test-key",
		"algorithm":          "RS256",
		"rotation_period":    86400,
		"verification_ttl":   86400,
		"allowed_client_ids": []string{"*"},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data:      keyData,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create key: %v", resp.Error())
	}

	// Rotate the key
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "key/test-key/rotate",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to rotate key: %v", resp.Error())
	}

	// Read the JWKS endpoint
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      ".well-known/keys",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("failed to read JWKS: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Parse the JWKS response
	rawBody, ok := resp.Data[logical.HTTPRawBody].([]byte)
	if !ok {
		t.Fatal("expected raw body to be []byte")
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawBody, &jwks); err != nil {
		t.Fatalf("failed to unmarshal JWKS: %v", err)
	}

	// After rotation, we should have at least 2 keys (current + previous in key ring)
	if len(jwks.Keys) < 2 {
		t.Errorf("expected at least 2 keys after rotation, got %d", len(jwks.Keys))
	}
}

// Made with Bob
