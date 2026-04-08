package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKey_Create(t *testing.T) {
	b, storage := getTestBackend(t)

	tests := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid key with defaults",
			data:    map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "valid key with RS256",
			data: map[string]interface{}{
				"algorithm":        "RS256",
				"rotation_period":  3600,
				"verification_ttl": 7200,
			},
			wantErr: false,
		},
		{
			name: "valid key with ES256",
			data: map[string]interface{}{
				"algorithm":        "ES256",
				"rotation_period":  3600,
				"verification_ttl": 3600,
			},
			wantErr: false,
		},
		{
			name: "valid key with allowed_client_ids",
			data: map[string]interface{}{
				"allowed_client_ids": []string{"client1", "client2"},
			},
			wantErr: false,
		},
		{
			name: "valid key with wildcard allowed_client_ids",
			data: map[string]interface{}{
				"allowed_client_ids": []string{"*"},
			},
			wantErr: false,
		},
		{
			name: "invalid algorithm",
			data: map[string]interface{}{
				"algorithm": "HS256",
			},
			wantErr: true,
			errMsg:  "invalid algorithm",
		},
		{
			name: "rotation_period too short",
			data: map[string]interface{}{
				"rotation_period": 30,
			},
			wantErr: true,
			errMsg:  "rotation_period must be at least one minute",
		},
		{
			name: "verification_ttl too long",
			data: map[string]interface{}{
				"rotation_period":  3600,
				"verification_ttl": 40000,
			},
			wantErr: true,
			errMsg:  "verification_ttl cannot be longer than 10x rotation_period",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "key/test-key",
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(context.Background(), req)

			if tc.wantErr {
				require.True(t, resp != nil && resp.IsError() || err != nil, "expected error")
				if tc.errMsg != "" && resp != nil && resp.Error() != nil {
					assert.Contains(t, resp.Error().Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.False(t, resp.IsError())

				// Verify response contains expected fields
				assert.Contains(t, resp.Data, "name")
				assert.Contains(t, resp.Data, "algorithm")
				assert.Contains(t, resp.Data, "rotation_period")
				assert.Contains(t, resp.Data, "verification_ttl")
				assert.Contains(t, resp.Data, "next_rotation")
			}
		})
	}
}

func TestKey_Read(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"algorithm":          "RS256",
			"rotation_period":    3600,
			"verification_ttl":   7200,
			"allowed_client_ids": []string{"client1"},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	// Read the key
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	// Verify response
	assert.Equal(t, "test-key", resp.Data["name"])
	assert.Equal(t, "RS256", resp.Data["algorithm"])
	assert.Equal(t, int64(3600), resp.Data["rotation_period"])
	assert.Equal(t, int64(7200), resp.Data["verification_ttl"])
	assert.Equal(t, []string{"client1"}, resp.Data["allowed_client_ids"])
	assert.Contains(t, resp.Data, "key_id")
	assert.Contains(t, resp.Data, "next_rotation")
}

func TestKey_Update(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"algorithm":        "RS256",
			"rotation_period":  3600,
			"verification_ttl": 7200,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Read to get original key_id
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	originalKeyID := resp.Data["key_id"]

	// Update the key
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"rotation_period":    7200,
			"verification_ttl":   14400,
			"allowed_client_ids": []string{"client1", "client2"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	// Verify update
	assert.Equal(t, int64(7200), resp.Data["rotation_period"])
	assert.Equal(t, int64(14400), resp.Data["verification_ttl"])
	assert.Equal(t, []string{"client1", "client2"}, resp.Data["allowed_client_ids"])

	// Read to verify key_id hasn't changed
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, originalKeyID, resp.Data["key_id"], "key_id should not change on update")
}

func TestKey_UpdateWithWildcard(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key with specific client IDs
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"allowed_client_ids": []string{"client1", "client2"},
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Update to wildcard
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"allowed_client_ids": []string{"*"},
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	// Verify wildcard was set
	assert.Equal(t, []string{"*"}, resp.Data["allowed_client_ids"])

	// Read to confirm
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"*"}, resp.Data["allowed_client_ids"])
}

func TestKey_Delete(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Delete the key
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// Verify key is deleted
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Nil(t, resp)
}

func TestKey_List(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create multiple keys
	keys := []string{"key1", "key2", "key3"}
	for _, keyName := range keys {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "key/" + keyName,
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.False(t, resp.IsError())
	}

	// List keys
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "key/",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	// Verify list contains all keys
	listedKeys, ok := resp.Data["keys"].([]string)
	require.True(t, ok)
	assert.ElementsMatch(t, keys, listedKeys)
}

func TestKey_Rotate(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"rotation_period":  3600,
			"verification_ttl": 7200,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Read to get original key_id
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	originalKeyID := resp.Data["key_id"].(string)

	// Wait a moment to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Rotate the key
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "key/test-key/rotate",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())

	newKeyID := resp.Data["key_id"].(string)
	assert.NotEqual(t, originalKeyID, newKeyID, "key_id should change after rotation")

	// Verify rotation updated next_rotation
	assert.Contains(t, resp.Data, "next_rotation")
}

func TestKey_RotateWithVerificationTTL(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create a test key
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"rotation_period":  3600,
			"verification_ttl": 7200,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Rotate with custom verification_ttl
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "key/test-key/rotate",
		Storage:   storage,
		Data: map[string]interface{}{
			"verification_ttl": 3600,
		},
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError())
	
	// Verify the rotate response includes the updated verification_ttl
	assert.Equal(t, int64(3600), resp.Data["verification_ttl"])

	// Read key to verify verification_ttl was persisted
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, int64(3600), resp.Data["verification_ttl"])
}

func TestKey_ExistenceCheck(t *testing.T) {
	b, storage := getTestBackend(t)
	backend := b.(*oauthBackend)

	// Check non-existent key
	exists, err := backend.pathKeyExistenceCheck(
		context.Background(),
		&logical.Request{Storage: storage},
		&framework.FieldData{
			Raw: map[string]interface{}{"name": "test-key"},
			Schema: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString},
			},
		},
	)
	require.NoError(t, err)
	assert.False(t, exists)

	// Create a key
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "key/test-key",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Check existing key
	exists, err = backend.pathKeyExistenceCheck(
		context.Background(),
		&logical.Request{Storage: storage},
		&framework.FieldData{
			Raw: map[string]interface{}{"name": "test-key"},
			Schema: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString},
			},
		},
	)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestKey_AllAlgorithms(t *testing.T) {
	b, storage := getTestBackend(t)

	algorithms := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "key/test-key-" + alg,
				Storage:   storage,
				Data: map[string]interface{}{
					"algorithm": alg,
				},
			}

			resp, err := b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError())

			// Read the key to get key_id
			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "key/test-key-" + alg,
				Storage:   storage,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, alg, resp.Data["algorithm"])
			assert.Contains(t, resp.Data, "key_id")
		})
	}
}

// Made with Bob