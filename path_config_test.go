package oauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected map[string]interface{}
		wantErr  bool
	}{
		{
			name: "valid configuration",
			config: map[string]interface{}{
				"client_id":         "test-client-id",
				"client_secret":     "test-client-secret",
				"userinfo_endpoint": "https://provider.example.com/userinfo",
			},
			expected: map[string]interface{}{
				"client_id":         "test-client-id",
				"userinfo_endpoint": "https://provider.example.com/userinfo",
			},
		},
		{
			name: "missing client_id",
			config: map[string]interface{}{
				"client_secret":     "test-client-secret",
				"userinfo_endpoint": "https://provider.example.com/userinfo",
			},
			wantErr: true,
		},
		{
			name: "missing client_secret",
			config: map[string]interface{}{
				"client_id":         "test-client-id",
				"userinfo_endpoint": "https://provider.example.com/userinfo",
			},
			wantErr: true,
		},
		{
			name: "missing userinfo_endpoint",
			config: map[string]interface{}{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, s := getTestBackend(t)
			testConfigCreate(t, b, s, tc.config, tc.wantErr)

			if !tc.wantErr {
				testConfigRead(t, b, s, tc.expected)

				// Test that updating one element retains the others
				tc.expected["client_id"] = "updated-client-id"
				configSubset := map[string]interface{}{
					"client_id":         "updated-client-id",
					"client_secret":     "test-client-secret",
					"userinfo_endpoint": "https://provider.example.com/userinfo",
				}

				testConfigUpdate(t, b, s, configSubset, false)
				testConfigRead(t, b, s, tc.expected)
			}
		})
	}
}

func TestConfigDelete(t *testing.T) {
	b, s := getTestBackend(t)

	// Create valid config
	config := map[string]interface{}{
		"client_id":         "test-client-id",
		"client_secret":     "test-client-secret",
		"userinfo_endpoint": "https://provider.example.com/userinfo",
	}

	testConfigCreate(t, b, s, config, false)

	// Verify config exists
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.IsError())

	// Delete config
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   s,
	})
	assert.NoError(t, err)
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Verify config is deleted
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func testConfigCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, wantErr bool) {
	t.Helper()
	testConfigCreateUpdate(t, b, logical.CreateOperation, s, d, wantErr)
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, wantErr bool) {
	t.Helper()
	testConfigCreateUpdate(t, b, logical.UpdateOperation, s, d, wantErr)
}

func testConfigCreateUpdate(t *testing.T, b logical.Backend, op logical.Operation, s logical.Storage, d map[string]interface{}, wantErr bool) {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      "config",
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

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	// Check that all expected keys are present
	for key, expectedValue := range expected {
		actualValue, ok := resp.Data[key]
		if !ok {
			t.Fatalf("expected key %s not found in response", key)
		}

		assert.Equal(t, expectedValue, actualValue, "value mismatch for key %s", key)
	}
}

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()

	config := &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 3600,
			MaxLeaseTTLVal:     86400,
		},
		StorageView: &logical.InmemStorage{},
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

// Made with Bob
