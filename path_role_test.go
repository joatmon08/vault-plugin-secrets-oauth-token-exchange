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
				"ttl":     3600,
				"max_ttl": 86400,
			},
			expected: map[string]interface{}{
				"name":    "test-role-all",
				"ttl":     int64(3600),
				"max_ttl": int64(86400),
			},
		},
		{
			name: "valid role with minimal fields",
			role: map[string]interface{}{
				"ttl":     1800,
				"max_ttl": 7200,
			},
			expected: map[string]interface{}{
				"name":    "test-role-minimal",
				"ttl":     int64(1800),
				"max_ttl": int64(7200),
			},
		},
		{
			name: "valid role with default values",
			role: map[string]interface{}{},
			expected: map[string]interface{}{
				"name":    "test-role-default",
				"ttl":     int64(3600),
				"max_ttl": int64(86400),
			},
		},
		{
			name: "invalid role - ttl greater than max_ttl",
			role: map[string]interface{}{
				"ttl":     86400,
				"max_ttl": 3600,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, s := getTestBackend(t)
			
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

	// Create initial role
	role := map[string]interface{}{
		"ttl":     3600,
		"max_ttl": 86400,
	}

	testRoleCreate(t, b, s, "test-role", role, false)

	// Update ttl
	roleUpdate := map[string]interface{}{
		"ttl":     7200,
		"max_ttl": 86400,
	}

	testRoleUpdate(t, b, s, "test-role", roleUpdate, false)

	// Verify update
	expected := map[string]interface{}{
		"name":    "test-role",
		"ttl":     int64(7200),
		"max_ttl": int64(86400),
	}

	testRoleRead(t, b, s, "test-role", expected)
}

func TestRoleDelete(t *testing.T) {
	b, s := getTestBackend(t)

	// Create valid role
	role := map[string]interface{}{
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

	// Create multiple roles
	roles := []string{"role1", "role2", "role3"}
	for _, roleName := range roles {
		role := map[string]interface{}{
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

	// Create a role
	role := map[string]interface{}{
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

	// Create role without specifying TTL values
	role := map[string]interface{}{}

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

// Made with Bob