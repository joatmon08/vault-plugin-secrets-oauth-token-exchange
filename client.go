package oauth

import (
	"fmt"

	"golang.org/x/oauth2"
)

// oauthClient is a client for interacting with OAuth 2.0 providers
type oauthClient struct {
	config       *oauthConfig
	oauth2Config *oauth2.Config
}

// newClient creates a new OAuth client from the configuration
func newClient(config *oauthConfig) (*oauthClient, error) {
	if config == nil {
		return nil, fmt.Errorf("client configuration is nil")
	}

	return &oauthClient{
		config: config,
	}, nil
}


// Made with Bob
