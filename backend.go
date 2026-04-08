package oauth

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// oauthBackend defines an object that extends the Vault backend
// and stores the OAuth token exchange client configuration
type oauthBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *oauthClient
}

// backend defines the target API backend for Vault.
// It must include each path and the secrets it will store.
func backend() *oauthBackend {
	var b = oauthBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathConfig(&b),
			pathRole(&b),
			pathKey(&b),
			pathToken(&b),
		),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears any client configuration for a new backend to be configured
func (b *oauthBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears an existing client configuration in the backend
func (b *oauthBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient locks the backend as it configures and creates a new client
func (b *oauthBackend) getClient(ctx context.Context, s logical.Storage) (*oauthClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("client configuration not found")
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	b.client = client
	return client, nil
}

// backendHelp should contain help information for the backend
const backendHelp = `
The OAuth Token Exchange secrets backend implements RFC 8693 for OAuth 2.0 Token Exchange.
It uses Vault as an OIDC provider to obtain subject tokens via the authorization code flow,
and Vault's identity secrets for actor tokens.

After mounting this backend, you must configure it with the OAuth provider settings
using the "config/" endpoint, and create roles using the "role/" endpoint.
`

// Made with Bob
