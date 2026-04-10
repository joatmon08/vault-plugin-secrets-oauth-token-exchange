// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend_Factory(t *testing.T) {
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

	if b == nil {
		t.Fatal("backend is nil")
	}
}

func TestBackend_Paths(t *testing.T) {
	b := backend()

	if b.Paths == nil {
		t.Fatal("backend paths are nil")
	}

	paths := b.Paths
	if len(paths) == 0 {
		t.Fatal("no paths defined")
	}

	// Basic sanity check that paths exist
	for _, path := range paths {
		if path.Pattern == "" {
			t.Error("found path with empty pattern")
		}
	}

	t.Logf("Backend has %d paths defined", len(paths))
}

// Made with Bob
