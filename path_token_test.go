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

			subjectTokenClaims, err := backend.verifySubjectToken(context.Background(), config, tc.token)

			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, subjectTokenClaims)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				assert.NoError(t, err)
				require.NotNil(t, subjectTokenClaims)
				assert.Equal(t, "user123", subjectTokenClaims.Subject)
				assert.Equal(t, "actor", subjectTokenClaims.MayAct[0].ClientID)
				assert.Equal(t, "actor-sub", subjectTokenClaims.MayAct[0].Subject)
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

func TestGeneratePayload(t *testing.T) {
	tests := []struct {
		name    string
		token   *accessToken
		wantErr bool
		check   func(t *testing.T, payload []byte)
	}{
		{
			name: "basic token with all fields",
			token: &accessToken{
				Issuer:   "http://127.0.0.1:8200/v1/identity/oidc",
				Subject:  "52b1da4c-0a60-f23a-3384-1d5837af487e",
				Audience: "helloworld-agent",
				Expiry:   1775586454,
				IssuedAt: 1775500054,
				ClientID: "test-client",
				Actors: map[string]interface{}{
					"sub":       "11111111-1111-1111-1111-111111111111",
					"client_id": "first-client",
				},
				Scope: "helloworld:read",
			},
			wantErr: false,
			check: func(t *testing.T, payload []byte) {
				var claims map[string]interface{}
				err := json.Unmarshal(payload, &claims)
				require.NoError(t, err)
				assert.Equal(t, "http://127.0.0.1:8200/v1/identity/oidc", claims["iss"])
				assert.Equal(t, "52b1da4c-0a60-f23a-3384-1d5837af487e", claims["sub"])
				assert.Equal(t, "helloworld-agent", claims["aud"])
				assert.Equal(t, float64(1775586454), claims["exp"])
				assert.Equal(t, float64(1775500054), claims["iat"])
				assert.Equal(t, "test-client", claims["client_id"])
				assert.Equal(t, "helloworld:read", claims["scope"])

				// Check act claim structure
				act, ok := claims["act"].(map[string]interface{})
				require.True(t, ok, "act should be a map")
				assert.Equal(t, "11111111-1111-1111-1111-111111111111", act["sub"])
				assert.Equal(t, "first-client", act["client_id"])
			},
		},
		{
			name: "token with nested act claims",
			token: &accessToken{
				Issuer:   "http://127.0.0.1:8200/v1/identity/oidc",
				Subject:  "064a698a-4133-7443-b89d-aecd885aa3ee",
				Audience: "test-client",
				Expiry:   1775586454,
				IssuedAt: 1775500054,
				ClientID: "test-client",
				Actors: map[string]interface{}{
					"sub":       "11111111-1111-1111-1111-111111111111",
					"client_id": "first-client",
					"act": map[string]interface{}{
						"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
						"client_id": "second-client",
					},
				},
				Scope: "helloworld:read",
			},
			wantErr: false,
			check: func(t *testing.T, payload []byte) {
				var claims map[string]interface{}
				err := json.Unmarshal(payload, &claims)
				require.NoError(t, err)

				// Check top-level claims
				assert.Equal(t, "http://127.0.0.1:8200/v1/identity/oidc", claims["iss"])
				assert.Equal(t, "064a698a-4133-7443-b89d-aecd885aa3ee", claims["sub"])
				assert.Equal(t, "test-client", claims["aud"])

				// Check act claim structure
				act, ok := claims["act"].(map[string]interface{})
				require.True(t, ok, "act should be a map")
				assert.Equal(t, "11111111-1111-1111-1111-111111111111", act["sub"])
				assert.Equal(t, "first-client", act["client_id"])

				// Check nested act claim
				nestedAct, ok := act["act"].(map[string]interface{})
				require.True(t, ok, "nested act should be a map")
				assert.Equal(t, "a1b2c3d4-5678-90ab-cdef-1234567890ab", nestedAct["sub"])
				assert.Equal(t, "second-client", nestedAct["client_id"])
			},
		},
		{
			name: "token with deeply nested act claims (3 levels)",
			token: &accessToken{
				Issuer:   "http://127.0.0.1:8200/v1/identity/oidc",
				Subject:  "064a698a-4133-7443-b89d-aecd885aa3ee",
				Audience: "test-client",
				Expiry:   1775586454,
				IssuedAt: 1775500054,
				ClientID: "test-client",
				Actors: map[string]interface{}{
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"client_id": "first-client",
					"act": map[string]interface{}{
						"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
						"client_id": "service-client-1",
						"act": map[string]interface{}{
							"sub":       "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
							"client_id": "service-client-2",
						},
					},
				},
				Scope: "helloworld:read helloworld:write",
			},
			wantErr: false,
			check: func(t *testing.T, payload []byte) {
				var claims map[string]interface{}
				err := json.Unmarshal(payload, &claims)
				require.NoError(t, err)

				// Check first level act
				act1, ok := claims["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "52b1da4c-0a60-f23a-3384-1d5837af487e", act1["sub"])
				assert.Equal(t, "first-client", act1["client_id"])

				// Check second level act
				act2, ok := act1["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "a1b2c3d4-5678-90ab-cdef-1234567890ab", act2["sub"])
				assert.Equal(t, "service-client-1", act2["client_id"])

				// Check third level act
				act3, ok := act2["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "f9e8d7c6-b5a4-3210-fedc-ba9876543210", act3["sub"])
				assert.Equal(t, "service-client-2", act3["client_id"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := tc.token.generatePayload()

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, payload)
				if tc.check != nil {
					tc.check(t, payload)
				}
			}
		})
	}
}

func TestSignPayload(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (*namedKey, []byte)
		wantErr bool
		errMsg  string
	}{
		{
			name: "successfully sign payload with RS256",
			setup: func(t *testing.T) (*namedKey, []byte) {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				jwk := &jose.JSONWebKey{
					Key:       privateKey,
					KeyID:     "94934611-ecd7-a35a-ce12-afa710cb5fb8",
					Algorithm: string(jose.RS256),
				}

				key := &namedKey{
					Algorithm:  string(jose.RS256),
					SigningKey: jwk,
				}

				payload := []byte(`{"iss":"http://127.0.0.1:8200/v1/identity/oidc","sub":"52b1da4c-0a60-f23a-3384-1d5837af487e","aud":"test-client"}`)
				return key, payload
			},
			wantErr: false,
		},
		{
			name: "successfully sign payload with nested act claims",
			setup: func(t *testing.T) (*namedKey, []byte) {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				jwk := &jose.JSONWebKey{
					Key:       privateKey,
					KeyID:     "94934611-ecd7-a35a-ce12-afa710cb5fb8",
					Algorithm: string(jose.RS256),
				}

				key := &namedKey{
					Algorithm:  string(jose.RS256),
					SigningKey: jwk,
				}

				token := &accessToken{
					Issuer:   "http://127.0.0.1:8200/v1/identity/oidc",
					Subject:  "064a698a-4133-7443-b89d-aecd885aa3ee",
					Audience: "test-client",
					Expiry:   time.Now().Add(1 * time.Hour).Unix(),
					IssuedAt: time.Now().Unix(),
					ClientID: "test-client",
					Actors: map[string]interface{}{
						"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						"client_id": "first-client",
						"act": map[string]interface{}{
							"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
							"client_id": "second-client",
						},
					},
					Scope: "helloworld:read",
				}

				payload, err := token.generatePayload()
				require.NoError(t, err)

				return key, payload
			},
			wantErr: false,
		},
		{
			name: "fail when signing key is nil",
			setup: func(t *testing.T) (*namedKey, []byte) {
				key := &namedKey{
					Algorithm:  string(jose.RS256),
					SigningKey: nil,
				}

				payload := []byte(`{"iss":"http://127.0.0.1:8200/v1/identity/oidc"}`)
				return key, payload
			},
			wantErr: true,
			errMsg:  "signing key is nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, payload := tc.setup(t)

			signedToken, err := key.signPayload(payload)

			if tc.wantErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, signedToken)

				// Verify the token can be parsed
				parsedToken, err := jwt.ParseSigned(signedToken)
				require.NoError(t, err)

				var claims map[string]interface{}
				err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
				require.NoError(t, err)

				// Verify basic structure
				assert.Contains(t, claims, "iss")
				assert.Contains(t, claims, "sub")
				assert.Contains(t, claims, "aud")
			}
		})
	}
}

func TestPerformTokenExchange(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, b *oauthBackend, storage logical.Storage) (subjectToken, actorToken string)
		wantErr bool
		errMsg  string
		check   func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "successful token exchange with nested act claims",
			setup: func(t *testing.T, b *oauthBackend, storage logical.Storage) (string, string) {
				// Create subject token with may_act claim
				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://localhost:8200/v1/identity/oidc/provider/test",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"client_id": "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
					"may_act": []map[string]string{
						{
							"client_id": "test-client",
							"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						},
						{
							"client_id": "first-client",
							"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
						},
					},
				})

				// Create actor token with nested act claims
				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "test-client",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
					"scope":     "helloworld:read",
					"act": map[string]interface{}{
						"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
						"client_id": "first-client",
					},
				})

				return subjectToken, actorToken
			},
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				// Verify response structure
				assert.Contains(t, result, "access_token")
				assert.Contains(t, result, "issued_token_type")
				assert.Contains(t, result, "token_type")
				assert.Equal(t, "Bearer", result["token_type"])
				assert.Equal(t, tokenTypeAccessToken, result["issued_token_type"])

				// Parse and verify the access token
				accessToken := result["access_token"].(string)
				parsedToken, err := jwt.ParseSigned(accessToken)
				require.NoError(t, err)

				var claims map[string]interface{}
				err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
				require.NoError(t, err)

				// Verify standard claims are preserved
				aud, ok := claims["aud"].(string)
				require.True(t, ok, "aud claim should be present")
				assert.Equal(t, "helloworld-agent", aud)

				clientID, ok := claims["client_id"].(string)
				require.True(t, ok, "client_id claim should be present")
				assert.Equal(t, "test-client", clientID)

				scope, ok := claims["scope"].(string)
				require.True(t, ok, "scope claim should be present")
				assert.Equal(t, "helloworld:read", scope)

				// Verify nested act claims are preserved
				act, ok := claims["act"].(map[string]interface{})
				require.True(t, ok, "act claim should be present")
				assert.Equal(t, "52b1da4c-0a60-f23a-3384-1d5837af487e", act["sub"])
				assert.Equal(t, "test-client", act["client_id"])

				// Verify nested act
				nestedAct, ok := act["act"].(map[string]interface{})
				require.True(t, ok, "nested act claim should be present")
				assert.Equal(t, "a1b2c3d4-5678-90ab-cdef-1234567890ab", nestedAct["sub"])
				assert.Equal(t, "first-client", nestedAct["client_id"])
			},
		},
		{
			name: "successful token exchange with deeply nested act claims (3 levels)",
			setup: func(t *testing.T, b *oauthBackend, storage logical.Storage) (string, string) {
				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://localhost:8200/v1/identity/oidc/provider/test",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"client_id": "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
					"may_act": []map[string]string{
						{
							"client_id": "test-client",
							"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						},
					},
				})

				// Create actor token with 3 levels of nested act claims
				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "test-client",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
					"act": map[string]interface{}{
						"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
						"client_id": "service-client-1",
						"act": map[string]interface{}{
							"sub":       "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
							"client_id": "service-client-2",
							"act": map[string]interface{}{
								"sub":       "11223344-5566-7788-99aa-bbccddeeff00",
								"client_id": "service-client-3",
							},
						},
					},
				})

				return subjectToken, actorToken
			},
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				accessToken := result["access_token"].(string)
				parsedToken, err := jwt.ParseSigned(accessToken)
				require.NoError(t, err)

				var claims map[string]interface{}
				err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
				require.NoError(t, err)

				// Verify standard claims are preserved
				aud, ok := claims["aud"].(string)
				require.True(t, ok, "aud claim should be present")
				assert.Equal(t, "helloworld-agent", aud)

				clientID, ok := claims["client_id"].(string)
				require.True(t, ok, "client_id claim should be present")
				assert.Equal(t, "test-client", clientID)

				scope, ok := claims["scope"].(string)
				require.True(t, ok, "scope claim should be present")
				assert.Equal(t, "helloworld:read", scope)

				// Verify 3 levels of nested act claims
				act, ok := claims["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "52b1da4c-0a60-f23a-3384-1d5837af487e", act["sub"])
				assert.Equal(t, "test-client", act["client_id"])

				act1, ok := act["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "a1b2c3d4-5678-90ab-cdef-1234567890ab", act1["sub"])
				assert.Equal(t, "service-client-1", act1["client_id"])

				act2, ok := act1["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "f9e8d7c6-b5a4-3210-fedc-ba9876543210", act2["sub"])
				assert.Equal(t, "service-client-2", act2["client_id"])

				act3, ok := act2["act"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "11223344-5566-7788-99aa-bbccddeeff00", act3["sub"])
				assert.Equal(t, "service-client-3", act3["client_id"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)
			backend := b.(*oauthBackend)

			// Setup config
			config := &oauthConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
			}
			entry, err := logical.StorageEntryJSON("config", config)
			require.NoError(t, err)
			err = storage.Put(context.Background(), entry)
			require.NoError(t, err)

			// Create a test key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)

			jwk := &jose.JSONWebKey{
				Key:       privateKey,
				KeyID:     "94934611-ecd7-a35a-ce12-afa710cb5fb8",
				Algorithm: string(jose.RS256),
			}

			key := &namedKey{
				name:             "test-key",
				Algorithm:        string(jose.RS256),
				SigningKey:       jwk,
				VerificationTTL:  24 * time.Hour,
				AllowedClientIDs: []string{"*"},
			}

			keyEntry, err := logical.StorageEntryJSON(keyStoragePath+"test-key", key)
			require.NoError(t, err)
			err = storage.Put(context.Background(), keyEntry)
			require.NoError(t, err)

			// Create a test role
			role := &roleEntry{
				Key:    "test-key",
				Issuer: "http://127.0.0.1:8200/v1/identity/oidc",
				TTL:    1 * time.Hour,
			}

			roleEntry, err := logical.StorageEntryJSON(roleStoragePrefix+"test-role", role)
			require.NoError(t, err)
			err = storage.Put(context.Background(), roleEntry)
			require.NoError(t, err)

			// Setup test tokens
			subjectToken, actorToken := tc.setup(t, backend, storage)

			// Perform token exchange
			result, err := backend.performTokenExchange(
				context.Background(),
				&logical.Request{Storage: storage},
				config,
				role,
				subjectToken,
				actorToken,
				grantTypeTokenExchange,
				"test-client",
				"helloworld-agent",
				"helloworld:read",
			)

			if tc.wantErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tc.check != nil {
					tc.check(t, result)
				}
			}
		})
	}
}


// TestVerifySubjectTokenWithJWKS tests subject token verification using JWKS
func TestVerifySubjectTokenWithJWKS(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyID := "test-key-id"
	
	// Create a JWK for the public key
	publicJWK := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	// Create a JWKS with the public key
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{publicJWK},
	}

	// Create a mock JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	t.Run("valid subject token with JWKS verification", func(t *testing.T) {
		b, _ := getTestBackend(t)

		// Create a signer with the private key
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
		)
		require.NoError(t, err)

		// Create claims with may_act
		claims := map[string]interface{}{
			"iss":       "https://issuer.example.com",
			"sub":       "user123",
			"aud":       "https://resource.example.com",
			"client_id": "client123",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"may_act": []map[string]interface{}{
				{
					"client_id": "actor-client",
					"sub":       "actor-sub",
				},
			},
		}

		// Sign the token
		builder := jwt.Signed(signer).Claims(claims)
		token, err := builder.CompactSerialize()
		require.NoError(t, err)

		// Create config with JWKS URI
		config := &oauthConfig{
			ClientID:            "client123",
			SubjectTokenJWKSURI: jwksServer.URL,
		}

		// Verify the token
		ob := b.(*oauthBackend)
		result, err := ob.verifySubjectToken(context.Background(), config, token)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "user123", result.Subject)
		assert.Len(t, result.MayAct, 1)
		assert.Equal(t, "actor-client", result.MayAct[0].ClientID)
		assert.Equal(t, "actor-sub", result.MayAct[0].Subject)
	})

	t.Run("invalid signature with JWKS verification", func(t *testing.T) {
		b, _ := getTestBackend(t)

		// Create a different key for signing (wrong key)
		wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: wrongKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
		)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"iss":       "https://issuer.example.com",
			"sub":       "user123",
			"aud":       "https://resource.example.com",
			"client_id": "client123",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"may_act": []map[string]interface{}{
				{
					"client_id": "actor-client",
					"sub":       "actor-sub",
				},
			},
		}

		builder := jwt.Signed(signer).Claims(claims)
		token, err := builder.CompactSerialize()
		require.NoError(t, err)

		config := &oauthConfig{
			ClientID:            "client123",
			SubjectTokenJWKSURI: jwksServer.URL,
		}

		// Verify should fail due to signature mismatch
		ob := b.(*oauthBackend)
		_, err = ob.verifySubjectToken(context.Background(), config, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to verify subject token with JWKS")
	})

	t.Run("missing key ID in token header", func(t *testing.T) {
		b, _ := getTestBackend(t)

		// Create signer without key ID
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"iss":       "https://issuer.example.com",
			"sub":       "user123",
			"aud":       "https://resource.example.com",
			"client_id": "client123",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"may_act": []map[string]interface{}{
				{
					"client_id": "actor-client",
					"sub":       "actor-sub",
				},
			},
		}

		builder := jwt.Signed(signer).Claims(claims)
		token, err := builder.CompactSerialize()
		require.NoError(t, err)

		config := &oauthConfig{
			ClientID:            "client123",
			SubjectTokenJWKSURI: jwksServer.URL,
		}

		ob := b.(*oauthBackend)
		_, err = ob.verifySubjectToken(context.Background(), config, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWT missing key ID in header")
	})

	t.Run("key not found in JWKS", func(t *testing.T) {
		b, _ := getTestBackend(t)

		// Create signer with a different key ID
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "non-existent-key"),
		)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"iss":       "https://issuer.example.com",
			"sub":       "user123",
			"aud":       "https://resource.example.com",
			"client_id": "client123",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"may_act": []map[string]interface{}{
				{
					"client_id": "actor-client",
					"sub":       "actor-sub",
				},
			},
		}

		builder := jwt.Signed(signer).Claims(claims)
		token, err := builder.CompactSerialize()
		require.NoError(t, err)

		config := &oauthConfig{
			ClientID:            "client123",
			SubjectTokenJWKSURI: jwksServer.URL,
		}

		ob := b.(*oauthBackend)
		_, err = ob.verifySubjectToken(context.Background(), config, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key not found for key ID")
	})

	t.Run("fallback to decode without JWKS URI", func(t *testing.T) {
		b, _ := getTestBackend(t)

		// Create a token without signature verification
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		require.NoError(t, err)

		claims := map[string]interface{}{
			"iss":       "https://issuer.example.com",
			"sub":       "user123",
			"aud":       "https://resource.example.com",
			"client_id": "client123",
			"exp":       time.Now().Add(1 * time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"may_act": []map[string]interface{}{
				{
					"client_id": "actor-client",
					"sub":       "actor-sub",
				},
			},
		}

		builder := jwt.Signed(signer).Claims(claims)
		token, err := builder.CompactSerialize()
		require.NoError(t, err)

		// Config without JWKS URI - should fall back to decodeToken
		config := &oauthConfig{
			ClientID: "client123",
		}

		ob := b.(*oauthBackend)
		result, err := ob.verifySubjectToken(context.Background(), config, token)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "user123", result.Subject)
	})

	t.Run("expired token with JWKS verification", func(t *testing.T) {
		b, _ := getTestBackend(t)

		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
		)
		require.NoError(t, err)

		// Create expired token
		claims := map[string]interface{}{
			"iss":       "https://issuer.example.com",
			"sub":       "user123",
			"aud":       "https://resource.example.com",
			"client_id": "client123",
			"exp":       time.Now().Add(-1 * time.Hour).Unix(), // Expired
			"iat":       time.Now().Add(-2 * time.Hour).Unix(),
			"may_act": []map[string]interface{}{
				{
					"client_id": "actor-client",
					"sub":       "actor-sub",
				},
			},
		}

		builder := jwt.Signed(signer).Claims(claims)
		token, err := builder.CompactSerialize()
		require.NoError(t, err)

		config := &oauthConfig{
			ClientID:            "client123",
			SubjectTokenJWKSURI: jwksServer.URL,
		}

		ob := b.(*oauthBackend)
		_, err = ob.verifySubjectToken(context.Background(), config, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JWT validation failed")
	})
}
// Made with Bob
