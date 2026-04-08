package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createJWTWithClaims creates a properly signed JWT for testing using go-jose
func createJWTWithClaims(claims map[string]interface{}) string {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create a signer
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		panic(err)
	}

	// Build and sign the JWT
	builder := jwt.Signed(signer).Claims(claims)
	token, err := builder.CompactSerialize()
	if err != nil {
		panic(err)
	}

	return token
}

func TestVerifySubjectToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing may_act claim",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'may_act' claim",
		},
		{
			name: "may_act missing client_id",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
				"may_act":   []map[string]string{{"sub": "actor-sub"}},
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'may_act' claim with 'client_id'",
		},
		{
			name: "may_act missing sub",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
				"may_act":   []map[string]string{{"client_id": "actor"}},
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'may_act' claim with 'sub'",
		},
		{
			name: "valid JWT with may_act claim",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
				"may_act":   []map[string]string{{"client_id": "actor", "sub": "actor-sub"}},
			}),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := getTestBackend(t)
			backend := b.(*oauthBackend)

			config := &oauthConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}

			mayAct, err := backend.verifySubjectToken(context.Background(), config, tc.token)

			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, mayAct)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				assert.NoError(t, err)
				require.NotNil(t, mayAct)
				assert.Equal(t, "actor", mayAct[0].ClientID)
				assert.Equal(t, "actor-sub", mayAct[0].Subject)
			}
		})
	}
}

func TestVerifyActorToken(t *testing.T) {
	tests := []struct {
		name           string
		config         *oauthConfig
		actorToken     string
		clientID       string
		mockResponse   map[string]interface{}
		mockStatusCode int
		wantErr        bool
		errMsg         string
	}{
		{
			name: "valid active token",
			config: &oauthConfig{
				VaultAddr:                 "", // Will be set to mock server URL
				VaultToken:                "test-token",
				IdentitySecretsEnginePath: "identity",
			},
			actorToken: "valid-actor-token",
			clientID:   "test-client",
			mockResponse: map[string]interface{}{
				"active": true,
			},
			mockStatusCode: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "inactive token",
			config: &oauthConfig{
				VaultAddr:                 "", // Will be set to mock server URL
				VaultToken:                "test-token",
				IdentitySecretsEnginePath: "identity",
			},
			actorToken: "inactive-actor-token",
			clientID:   "test-client",
			mockResponse: map[string]interface{}{
				"active": false,
			},
			mockStatusCode: http.StatusOK,
			wantErr:        true,
			errMsg:         "actor token is not active",
		},
		{
			name: "missing vault_token",
			config: &oauthConfig{
				VaultAddr:                 "http://localhost:8200",
				VaultToken:                "",
				IdentitySecretsEnginePath: "identity",
			},
			actorToken: "test-token",
			clientID:   "test-client",
			wantErr:    true,
			errMsg:     "vault_token not configured",
		},
		{
			name: "missing vault_addr",
			config: &oauthConfig{
				VaultAddr:                 "",
				VaultToken:                "test-token",
				IdentitySecretsEnginePath: "identity",
			},
			actorToken: "test-token",
			clientID:   "test-client",
			wantErr:    true,
			errMsg:     "vault_addr not configured",
		},
		{
			name: "missing identity_secrets_engine_path",
			config: &oauthConfig{
				VaultAddr:                 "http://localhost:8200",
				VaultToken:                "test-token",
				IdentitySecretsEnginePath: "",
			},
			actorToken: "test-token",
			clientID:   "test-client",
			wantErr:    true,
			errMsg:     "identity_secrets_engine_path not configured",
		},
		{
			name: "missing active field in response",
			config: &oauthConfig{
				VaultAddr:                 "", // Will be set to mock server URL
				VaultToken:                "test-token",
				IdentitySecretsEnginePath: "identity",
			},
			actorToken: "test-token",
			clientID:   "test-client",
			mockResponse: map[string]interface{}{
				"some_other_field": "value",
			},
			mockStatusCode: http.StatusOK,
			wantErr:        true,
			errMsg:         "missing 'active' field",
		},
		{
			name: "with vault namespace",
			config: &oauthConfig{
				VaultAddr:                 "", // Will be set to mock server URL
				VaultToken:                "test-token",
				VaultNamespace:            "test-namespace",
				IdentitySecretsEnginePath: "identity",
			},
			actorToken: "valid-actor-token",
			clientID:   "test-client",
			mockResponse: map[string]interface{}{
				"active": true,
			},
			mockStatusCode: http.StatusOK,
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock HTTP server if we need to test API calls
			var mockServer *httptest.Server
			if tc.mockResponse != nil {
				mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify the request (Vault client uses PUT for Write operations)
					assert.Equal(t, "PUT", r.Method)
					assert.Contains(t, r.URL.Path, "/identity/oidc/introspect")

					// Check for namespace header if configured
					if tc.config.VaultNamespace != "" {
						assert.Equal(t, tc.config.VaultNamespace, r.Header.Get("X-Vault-Namespace"))
					}

					// Check for token header
					assert.Equal(t, tc.config.VaultToken, r.Header.Get("X-Vault-Token"))

					// Return mock response
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.mockStatusCode)

					response := map[string]interface{}{
						"data": tc.mockResponse,
					}
					json.NewEncoder(w).Encode(response)
				}))
				defer mockServer.Close()

				// Set the mock server URL
				tc.config.VaultAddr = mockServer.URL
			}

			// Create backend
			b, _ := getTestBackend(t)
			backend := b.(*oauthBackend)

			// Create a mock request
			req := &logical.Request{}

			// Call verifyActorToken
			err := backend.verifyActorToken(context.Background(), req, tc.config, tc.actorToken, tc.clientID)

			// Check results
			if tc.wantErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
func TestDecodeToken(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour).Unix()
	pastTime := time.Now().Add(-24 * time.Hour).Unix()

	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "invalid JWT - not enough parts",
			token:   "invalid.token",
			wantErr: true,
			errMsg:  "compact JWS format must have three parts",
		},
		{
			name:    "invalid JWT - single part",
			token:   "invalidtoken",
			wantErr: true,
			errMsg:  "compact JWS format must have three parts",
		},
		{
			name:    "invalid JWT - bad base64 encoding",
			token:   "header.!!!invalid-base64!!!.signature",
			wantErr: true,
			errMsg:  "illegal base64 data",
		},
		{
			name:    "invalid JWT - not valid JSON",
			token:   "header." + base64.RawURLEncoding.EncodeToString([]byte("not valid json")) + ".signature",
			wantErr: true,
			errMsg:  "illegal base64 data",
		},
		{
			name: "invalid JWT - missing iss claim",
			token: createJWTWithClaims(map[string]interface{}{
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'iss' claim",
		},
		{
			name: "invalid JWT - missing sub claim",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"aud":       "test",
				"client_id": "test-client",
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'sub' claim",
		},
		{
			name: "invalid JWT - missing client_id claim",
			token: createJWTWithClaims(map[string]interface{}{
				"iss": "test-issuer",
				"sub": "user123",
				"aud": "test",
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'client_id' claim",
		},
		{
			name: "invalid JWT - missing aud claim",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"client_id": "test-client",
			}),
			wantErr: true,
			errMsg:  "JWT missing required 'aud' claim",
		},
		{
			name: "invalid JWT - expired token",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
				"exp":       pastTime,
			}),
			wantErr: true,
			errMsg:  "token is expired",
		},
		{
			name: "valid JWT - with all required claims and future expiration",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
				"exp":       futureTime,
			}),
			wantErr: false,
		},
		{
			name: "valid JWT - without exp claim",
			token: createJWTWithClaims(map[string]interface{}{
				"iss":       "test-issuer",
				"sub":       "user123",
				"aud":       "test",
				"client_id": "test-client",
			}),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := decodeToken(tc.token)

			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, claims)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, claims)
				// Verify required claims are present
				assert.Contains(t, claims, "iss")
				assert.Contains(t, claims, "sub")
				assert.Contains(t, claims, "client_id")
				assert.Contains(t, claims, "aud")
			}
		})
	}
}

// Made with Bob
