// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestRole(t *testing.T) {
	tests := []struct {
		name     string
		role     map[string]interface{}
		expected map[string]interface{}
		wantErr  bool
	}{
		{
			name: "valid role with all fields",
			role: map[string]interface{}{
				"key":     "test-key",
				"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
				"ttl":     3600,
				"max_ttl": 86400,
			},
			expected: map[string]interface{}{
				"name":    "test-role-all",
				"key":     "test-key",
				"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
				"ttl":     int64(3600),
				"max_ttl": int64(86400),
			},
		},
		{
			name: "valid role with minimal fields",
			role: map[string]interface{}{
				"key":     "test-key",
				"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
				"ttl":     1800,
				"max_ttl": 7200,
			},
			expected: map[string]interface{}{
				"name":    "test-role-minimal",
				"key":     "test-key",
				"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
				"ttl":     int64(1800),
				"max_ttl": int64(7200),
			},
		},
		{
			name: "valid role with default values",
			role: map[string]interface{}{
				"key":    "test-key",
				"issuer": "http://127.0.0.1:8200/v1/identity/oidc",
			},
			expected: map[string]interface{}{
				"name":    "test-role-default",
				"key":     "test-key",
				"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
				"ttl":     int64(3600),
				"max_ttl": int64(86400),
			},
		},
		{
			name: "invalid role - ttl greater than max_ttl",
			role: map[string]interface{}{
				"key":     "test-key",
				"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
				"ttl":     86400,
				"max_ttl": 3600,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, s := getTestBackend(t)

			// Create a test key first
			createTestKey(t, b, s, "test-key")

			var roleName string
			if tc.wantErr {
				roleName = "test-role-error"
			} else {
				roleName = tc.expected["name"].(string)
			}

			testRoleCreate(t, b, s, roleName, tc.role, tc.wantErr)

			if !tc.wantErr {
				testRoleRead(t, b, s, roleName, tc.expected)
			}
		})
	}
}

func TestRoleUpdate(t *testing.T) {
	b, s := getTestBackend(t)

	// Create a test key first
	createTestKey(t, b, s, "test-key")

	// Create initial role
	role := map[string]interface{}{
		"key":     "test-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     3600,
		"max_ttl": 86400,
	}

	testRoleCreate(t, b, s, "test-role", role, false)

	// Update ttl
	roleUpdate := map[string]interface{}{
		"key":     "test-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     7200,
		"max_ttl": 86400,
	}

	testRoleUpdate(t, b, s, "test-role", roleUpdate, false)

	// Verify update
	expected := map[string]interface{}{
		"name":    "test-role",
		"key":     "test-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     int64(7200),
		"max_ttl": int64(86400),
	}

	testRoleRead(t, b, s, "test-role", expected)
}

func TestRoleDelete(t *testing.T) {
	b, s := getTestBackend(t)

	// Create a test key first
	createTestKey(t, b, s, "test-key")

	// Create valid role
	role := map[string]interface{}{
		"key":     "test-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     3600,
		"max_ttl": 86400,
	}

	testRoleCreate(t, b, s, "test-role", role, false)

	// Verify role exists
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsError())

	// Delete role
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "role/test-role",
		Storage:   s,
	})
	assert.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Verify role is deleted
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func TestRoleList(t *testing.T) {
	b, s := getTestBackend(t)

	// Create a test key first
	createTestKey(t, b, s, "test-key")

	// Create multiple roles
	roles := []string{"role1", "role2", "role3"}
	for _, roleName := range roles {
		role := map[string]interface{}{
			"key":     "test-key",
			"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
			"ttl":     3600,
			"max_ttl": 86400,
		}
		testRoleCreate(t, b, s, roleName, role, false)
	}

	// List roles
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "role/",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsError())

	keys, ok := resp.Data["keys"].([]string)
	assert.True(t, ok)
	assert.ElementsMatch(t, roles, keys)
}

func TestRoleExistenceCheck(t *testing.T) {
	b, s := getTestBackend(t)

	// Create a test key first
	createTestKey(t, b, s, "test-key")

	// Create a role
	role := map[string]interface{}{
		"key":     "test-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     3600,
		"max_ttl": 86400,
	}
	testRoleCreate(t, b, s, "test-role", role, false)

	// Check existence of existing role
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   s,
	}

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name": "test-role",
		},
		Schema: pathRole(b.(*oauthBackend))[0].Fields,
	}

	exists, err := b.(*oauthBackend).pathRoleExistenceCheck(context.Background(), req, data)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Check existence of non-existing role
	data = &framework.FieldData{
		Raw: map[string]interface{}{
			"name": "non-existing-role",
		},
		Schema: pathRole(b.(*oauthBackend))[0].Fields,
	}

	exists, err = b.(*oauthBackend).pathRoleExistenceCheck(context.Background(), req, data)
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestRoleDefaultValues(t *testing.T) {
	b, s := getTestBackend(t)

	// Create a test key first
	createTestKey(t, b, s, "test-key")

	// Create role without specifying TTL values
	role := map[string]interface{}{
		"key":    "test-key",
		"issuer": "http://127.0.0.1:8200/v1/identity/oidc",
	}

	testRoleCreate(t, b, s, "test-role", role, false)

	// Read and verify default values
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsError())

	// Verify default TTL values
	assert.Equal(t, int64(3600), resp.Data["ttl"])
	assert.Equal(t, int64(86400), resp.Data["max_ttl"])
}

func TestRoleDefaultIssuer(t *testing.T) {
	b, s := getTestBackend(t)

	// Create a test key first
	createTestKey(t, b, s, "test-key")

	// Create role without specifying issuer
	role := map[string]interface{}{
		"key":     "test-key",
		"ttl":     3600,
		"max_ttl": 86400,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation:  logical.CreateOperation,
		Path:       "role/test-role-default-issuer",
		Data:       role,
		Storage:    s,
		MountPoint: "oauth-token-exchange/",
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsError())

	// Verify warning is present
	assert.NotEmpty(t, resp.Warnings)
	assert.Contains(t, resp.Warnings[0], "No issuer provided")
	assert.Contains(t, resp.Warnings[0], "/v1/oauth-token-exchange/")

	// Read and verify the role has the default issuer
	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role-default-issuer",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.NotNil(t, readResp)
	assert.False(t, readResp.IsError())

	// Verify the issuer is set to the default path-based value
	assert.Equal(t, "/v1/oauth-token-exchange/", readResp.Data["issuer"])
}

func TestRoleWithNonExistentKey(t *testing.T) {
	b, s := getTestBackend(t)

	// Try to create role with non-existent key
	role := map[string]interface{}{
		"key":     "non-existent-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     3600,
		"max_ttl": 86400,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Data:      role,
		Storage:   s,
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "does not exist")
}
func TestRoleWithScopesSupported(t *testing.T) {
	b, s := getTestBackend(t)

	// First create a key
	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   s,
		Data:      map[string]interface{}{},
	}
	keyResp, err := b.HandleRequest(context.Background(), keyReq)
	assert.NoError(t, err)
	if keyResp != nil && keyResp.IsError() {
		t.Fatalf("failed to create key: %v", keyResp.Error())
	}

	// Create some scopes
	scopeData := map[string]interface{}{
		"template":    `{"groups": {{identity.entity.groups.names}}}`,
		"description": "Groups scope",
	}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/groups",
		Data:      scopeData,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	scopeData = map[string]interface{}{
		"template":    `{"email": {{identity.entity.metadata.email}}}`,
		"description": "Email scope",
	}
	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/email",
		Data:      scopeData,
		Storage:   s,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Create role with scopes_supported
	role := map[string]interface{}{
		"key":              "test-key",
		"issuer":           "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":              3600,
		"max_ttl":          86400,
		"scopes_supported": []string{"groups", "email"},
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Data:      role,
		Storage:   s,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Read the role back
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   s,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Data)

	// Verify scopes_supported is present
	scopesSupported, ok := resp.Data["scopes_supported"]
	assert.True(t, ok, "scopes_supported should be present in response")
	assert.NotNil(t, scopesSupported)

	// Verify it's a slice with the correct values
	scopesList, ok := scopesSupported.([]string)
	assert.True(t, ok, "scopes_supported should be a string slice")
	assert.Equal(t, 2, len(scopesList))
	assert.Contains(t, scopesList, "groups")
	assert.Contains(t, scopesList, "email")
}

func TestRoleWithNonExistentScope(t *testing.T) {
	b, s := getTestBackend(t)

	// First create a key
	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   s,
		Data:      map[string]interface{}{},
	}
	keyResp, err := b.HandleRequest(context.Background(), keyReq)
	assert.NoError(t, err)
	if keyResp != nil && keyResp.IsError() {
		t.Fatalf("failed to create key: %v", keyResp.Error())
	}

	// Try to create role with non-existent scope
	role := map[string]interface{}{
		"key":              "test-key",
		"issuer":           "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":              3600,
		"max_ttl":          86400,
		"scopes_supported": []string{"non-existent-scope"},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Data:      role,
		Storage:   s,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.IsError())
	assert.Contains(t, resp.Error().Error(), "does not exist")
}

func TestRoleUpdateWithScopesSupported(t *testing.T) {
	b, s := getTestBackend(t)

	// First create a key
	keyReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   s,
		Data:      map[string]interface{}{},
	}
	keyResp, err := b.HandleRequest(context.Background(), keyReq)
	assert.NoError(t, err)
	if keyResp != nil && keyResp.IsError() {
		t.Fatalf("failed to create key: %v", keyResp.Error())
	}

	// Create a scope
	scopeData := map[string]interface{}{
		"template":    `{"groups": {{identity.entity.groups.names}}}`,
		"description": "Groups scope",
	}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/groups",
		Data:      scopeData,
		Storage:   s,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Create role without scopes_supported
	role := map[string]interface{}{
		"key":     "test-key",
		"issuer":  "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":     3600,
		"max_ttl": 86400,
	}

	req = &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Data:      role,
		Storage:   s,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Update role to add scopes_supported
	updateData := map[string]interface{}{
		"key":              "test-key",
		"issuer":           "http://127.0.0.1:8200/v1/identity/oidc",
		"ttl":              3600,
		"max_ttl":          86400,
		"scopes_supported": []string{"groups"},
	}

	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/test-role",
		Data:      updateData,
		Storage:   s,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Nil(t, resp)

	// Read the role back
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/test-role",
		Storage:   s,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Data)

	// Verify scopes_supported is present
	scopesSupported, ok := resp.Data["scopes_supported"]
	assert.True(t, ok, "scopes_supported should be present in response")
	assert.NotNil(t, scopesSupported)

	// Verify it's a slice with the correct value
	scopesList, ok := scopesSupported.([]string)
	assert.True(t, ok, "scopes_supported should be a string slice")
	assert.Equal(t, 1, len(scopesList))
	assert.Contains(t, scopesList, "groups")
}


func testRoleCreate(t *testing.T, b logical.Backend, s logical.Storage, name string, d map[string]interface{}, wantErr bool) {
	t.Helper()
	testRoleCreateUpdate(t, b, logical.CreateOperation, s, name, d, wantErr)
}

func testRoleUpdate(t *testing.T, b logical.Backend, s logical.Storage, name string, d map[string]interface{}, wantErr bool) {
	t.Helper()
	testRoleCreateUpdate(t, b, logical.UpdateOperation, s, name, d, wantErr)
}

func testRoleCreateUpdate(t *testing.T, b logical.Backend, op logical.Operation, s logical.Storage, name string, d map[string]interface{}, wantErr bool) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      "role/" + name,
		Data:      d,
		Storage:   s,
	})

	if !wantErr && err != nil {
		t.Fatal(err)
	}

	if !wantErr && resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	if wantErr {
		assert.True(t, (resp != nil && resp.IsError()) || err != nil, "expected error, got nil")
	}
}

func testRoleRead(t *testing.T, b logical.Backend, s logical.Storage, name string, expected map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/" + name,
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Check that all expected keys are present and match
	for key, expectedValue := range expected {
		actualValue, ok := resp.Data[key]
		if !ok {
			t.Fatalf("expected key %s not found in response. Available keys: %v", key, resp.Data)
		}

		assert.Equal(t, expectedValue, actualValue, "value mismatch for key %s", key)
	}
}

// createTestKey is a helper function to create a test signing key
func createTestKey(t *testing.T, b logical.Backend, s logical.Storage, name string) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/" + name,
		Data: map[string]interface{}{
			"algorithm": "RS256",
		},
		Storage: s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

// Made with Bob
