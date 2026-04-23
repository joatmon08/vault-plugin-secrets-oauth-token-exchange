// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathScope(t *testing.T) {
	b, storage := getTestBackend(t)

	t.Run("Create Scope", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "scope/test-scope",
			Storage:   storage,
			Data: map[string]interface{}{
				"template":    `{"custom_claim": "test-value"}`,
				"description": "Test scope for unit tests",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("bad: %#v", resp)
		}
	})

	t.Run("Read Scope", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "scope/test-scope",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response")
		}

		if resp.Data["template"] != `{"custom_claim": "test-value"}` {
			t.Fatalf("bad template: %v", resp.Data["template"])
		}
		if resp.Data["description"] != "Test scope for unit tests" {
			t.Fatalf("bad description: %v", resp.Data["description"])
		}
	})

	t.Run("List Scopes", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ListOperation,
			Path:      "scope/",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response")
		}

		keys := resp.Data["keys"].([]string)
		if len(keys) != 1 || keys[0] != "test-scope" {
			t.Fatalf("bad keys: %v", keys)
		}
	})

	t.Run("Update Scope", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "scope/test-scope",
			Storage:   storage,
			Data: map[string]interface{}{
				"template":    `{"updated_claim": "updated-value"}`,
				"description": "Updated test scope",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("bad: %#v", resp)
		}

		// Verify update
		readReq := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "scope/test-scope",
			Storage:   storage,
		}

		readResp, err := b.HandleRequest(context.Background(), readReq)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		if readResp.Data["template"] != `{"updated_claim": "updated-value"}` {
			t.Fatalf("bad template after update: %v", readResp.Data["template"])
		}
	})

	t.Run("Invalid Template JSON", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "scope/invalid-scope",
			Storage:   storage,
			Data: map[string]interface{}{
				"template":    `{invalid json}`,
				"description": "Invalid scope",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("expected error for invalid JSON template")
		}
	})

	t.Run("Reserved Claim in Template", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "scope/reserved-scope",
			Storage:   storage,
			Data: map[string]interface{}{
				"template":    `{"iss": "should-not-be-allowed"}`,
				"description": "Scope with reserved claim",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("expected error for reserved claim in template")
		}
	})

	t.Run("Delete Scope", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "scope/test-scope",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("bad: %#v", resp)
		}

		// Verify deletion
		readReq := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "scope/test-scope",
			Storage:   storage,
		}

		readResp, err := b.HandleRequest(context.Background(), readReq)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if readResp != nil {
			t.Fatal("expected nil response after deletion")
		}
	})
}

func TestScopeWithRole(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a key first
	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"rotation_period":    "24h",
			"verification_ttl":   "1h",
			"allowed_client_ids": []string{"*"},
		},
	}
	_, err := b.HandleRequest(context.Background(), keyReq)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	// Create a scope
	scopeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/profile",
		Storage:   storage,
		Data: map[string]interface{}{
			"template":    `{"email": "user@example.com", "name": "test-user"}`,
			"description": "Profile scope",
		},
	}
	_, err = b.HandleRequest(context.Background(), scopeReq)
	if err != nil {
		t.Fatalf("failed to create scope: %v", err)
	}

	t.Run("Create Role with Scopes", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/test-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"key":               "test-key",
				"issuer":            "https://example.com",
				"ttl":               3600,
				"max_ttl":           86400,
				"scopes_supported":  []string{"profile"},
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp != nil && resp.IsError() {
			t.Fatalf("bad: %#v", resp)
		}
	})

	t.Run("Read Role with Scopes", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "role/test-role",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response")
		}

		scopes := resp.Data["scopes_supported"].([]string)
		if len(scopes) != 1 || scopes[0] != "profile" {
			t.Fatalf("bad scopes: %v", scopes)
		}
	})

	t.Run("Cannot Delete Scope Referenced by Role", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "scope/profile",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("expected error when deleting scope referenced by role")
		}
	})

	t.Run("Role with Non-existent Scope", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "role/invalid-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"key":               "test-key",
				"issuer":            "https://example.com",
				"scopes_supported":  []string{"non-existent-scope"},
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatal("expected error for non-existent scope")
		}
	})
}

// Made with Bob
