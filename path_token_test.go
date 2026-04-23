// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

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
	// Generate a test RSA key pair for signing tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a signer
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-id"),
	)
	require.NoError(t, err)

	// Create valid token claims
	now := time.Now()
	validClaims := map[string]interface{}{
		"iss":       "https://vault.example.com",
		"sub":       "test-subject",
		"aud":       "test-audience",
		"exp":       now.Add(1 * time.Hour).Unix(),
		"iat":       now.Unix(),
		"client_id": "test-client",
	}

	// Create a valid signed token
	validToken, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
	require.NoError(t, err)

	// Create an expired token
	expiredClaims := map[string]interface{}{
		"iss":       "https://vault.example.com",
		"sub":       "test-subject",
		"aud":       "test-audience",
		"exp":       now.Add(-1 * time.Hour).Unix(),
		"iat":       now.Add(-2 * time.Hour).Unix(),
		"client_id": "test-client",
	}
	expiredToken, err := jwt.Signed(signer).Claims(expiredClaims).CompactSerialize()
	require.NoError(t, err)

	tests := []struct {
		name       string
		role       *roleEntry
		actorToken string
		setupJWKS  bool
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid token with JWKS verification",
			role: &roleEntry{
				Name:              "test-role",
				ActorTokenJWKSURI: "", // Will be set to mock server URL
			},
			actorToken: validToken,
			setupJWKS:  true,
			wantErr:    false,
		},
		{
			name: "expired token",
			role: &roleEntry{
				Name:              "test-role",
				ActorTokenJWKSURI: "", // Will be set to mock server URL
			},
			actorToken: expiredToken,
			setupJWKS:  true,
			wantErr:    true,
			errMsg:     "validation failed",
		},
		{
			name: "missing actor_token_jwks_uri",
			role: &roleEntry{
				Name:              "test-role",
				ActorTokenJWKSURI: "",
			},
			actorToken: validToken,
			setupJWKS:  false,
			wantErr:    true,
			errMsg:     "actor_token_jwks_uri not configured",
		},
		{
			name: "invalid token format",
			role: &roleEntry{
				Name:              "test-role",
				ActorTokenJWKSURI: "", // Will be set to mock server URL
			},
			actorToken: "invalid-token",
			setupJWKS:  true,
			wantErr:    true,
			errMsg:     "failed to parse JWT",
		},
		{
			name: "valid token with Vault identity JWKS format (multiple keys)",
			role: &roleEntry{
				Name:              "test-role",
				ActorTokenJWKSURI: "", // Will be set to mock server URL
			},
			actorToken: validToken,
			setupJWKS:  true,
			wantErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock JWKS server if needed
			var mockServer *httptest.Server
			if tc.setupJWKS {
				mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify the request
					assert.Equal(t, "GET", r.Method)

					// Create JWKS response with the public key
					publicKey := privateKey.Public()
					jwk := jose.JSONWebKey{
						Key:       publicKey,
						KeyID:     "test-key-id",
						Algorithm: string(jose.RS256),
						Use:       "sig",
					}

					var jwks jose.JSONWebKeySet

					// For the Vault identity JWKS format test, include multiple keys
					if tc.name == "valid token with Vault identity JWKS format (multiple keys)" {
						// Generate another key to simulate multiple keys in JWKS
						otherPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
						otherPublicKey := otherPrivateKey.Public()
						otherJwk := jose.JSONWebKey{
							Key:       otherPublicKey,
							KeyID:     "other-key-id",
							Algorithm: string(jose.RS256),
							Use:       "sig",
						}
						jwks = jose.JSONWebKeySet{
							Keys: []jose.JSONWebKey{otherJwk, jwk}, // Our key is second
						}
					} else {
						jwks = jose.JSONWebKeySet{
							Keys: []jose.JSONWebKey{jwk},
						}
					}

					// Return JWKS response
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(jwks)
				}))
				defer mockServer.Close()

				// Set the mock server URL
				tc.role.ActorTokenJWKSURI = mockServer.URL
			}

			// Create backend
			b, _ := getTestBackend(t)
			backend := b.(*oauthBackend)

			// Create a mock request
			req := &logical.Request{}

			// Call verifyActorToken
			err := backend.verifyActorToken(context.Background(), req, tc.role, tc.actorToken)

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

func TestTokenExchangeWithScopes(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create config
	configReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "test-client",
			"client_secret": "test-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), configReq)
	require.NoError(t, err)

	// Create a key
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
	_, err = b.HandleRequest(context.Background(), keyReq)
	require.NoError(t, err)

	// Create scopes
	profileScopeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/profile",
		Storage:   storage,
		Data: map[string]interface{}{
			"template":    `{"email": "test@example.com", "name": "Test User"}`,
			"description": "Profile scope",
		},
	}
	_, err = b.HandleRequest(context.Background(), profileScopeReq)
	require.NoError(t, err)

	groupsScopeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/groups",
		Storage:   storage,
		Data: map[string]interface{}{
			"template":    `{"groups": ["admin", "users"]}`,
			"description": "Groups scope",
		},
	}
	_, err = b.HandleRequest(context.Background(), groupsScopeReq)
	require.NoError(t, err)

	// Create a role with scopes
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"key":               "test-key",
			"issuer":            "https://example.com",
			"scopes_supported":  []string{"profile", "groups"},
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Create subject and actor tokens
	subjectToken := createJWTWithClaims(map[string]interface{}{
		"iss":       "test-issuer",
		"sub":       "user123",
		"aud":       "test",
		"client_id": "test-client",
		"may_act":   []map[string]string{{"client_id": "test-role", "sub": "test-entity"}},
	})

	actorToken := createJWTWithClaims(map[string]interface{}{
		"iss":       "test-issuer",
		"sub":       "test-entity",
		"aud":       "test",
		"client_id": "test-role",
	})

	// Perform token exchange with scopes
	tokenReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/test-role",
		Storage:   storage,
		EntityID:  "test-entity",
		Data: map[string]interface{}{
			"subject_token": subjectToken,
			"actor_token":   actorToken,
			"audience":      "test-audience",
			"scope":         "profile groups",
		},
	}

	resp, err := b.HandleRequest(context.Background(), tokenReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "expected no error, got: %v", resp.Error())

	// Verify the access token contains scope template claims
	accessToken, ok := resp.Data["access_token"].(string)
	require.True(t, ok, "expected access_token to be a string")
	require.NotEmpty(t, accessToken)

	// Parse the access token to verify claims
	parsedToken, err := jwt.ParseSigned(accessToken)
	require.NoError(t, err)

	var claims map[string]interface{}
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	// Verify standard claims
	assert.Equal(t, "https://example.com", claims["iss"])
	assert.Equal(t, "user123", claims["sub"])
	assert.Equal(t, "test-audience", claims["aud"])
	assert.Equal(t, "profile groups", claims["scope"])

	// Verify scope template claims were added
	assert.Equal(t, "test@example.com", claims["email"], "expected email from profile scope template")
	assert.Equal(t, "Test User", claims["name"], "expected name from profile scope template")
	
	groups, ok := claims["groups"].([]interface{})
	require.True(t, ok, "expected groups to be an array")
	assert.Len(t, groups, 2)
	assert.Contains(t, groups, "admin")
	assert.Contains(t, groups, "users")
}

func TestTokenExchangeWithMixedScopes(t *testing.T) {
	b, storage := getTestBackend(t)

	// Create config
	configReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     "test-client",
			"client_secret": "test-secret",
		},
	}
	_, err := b.HandleRequest(context.Background(), configReq)
	require.NoError(t, err)

	// Create a key
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
	_, err = b.HandleRequest(context.Background(), keyReq)
	require.NoError(t, err)

	// Create only one scope with a template
	profileScopeReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "scope/profile",
		Storage:   storage,
		Data: map[string]interface{}{
			"template":    `{"email": "test@example.com"}`,
			"description": "Profile scope",
		},
	}
	_, err = b.HandleRequest(context.Background(), profileScopeReq)
	require.NoError(t, err)

	// Create a role with only profile scope supported
	roleReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"key":               "test-key",
			"issuer":            "https://example.com",
			"scopes_supported":  []string{"profile"},
		},
	}
	_, err = b.HandleRequest(context.Background(), roleReq)
	require.NoError(t, err)

	// Create subject and actor tokens
	subjectToken := createJWTWithClaims(map[string]interface{}{
		"iss":       "test-issuer",
		"sub":       "user123",
		"aud":       "test",
		"client_id": "test-client",
		"may_act":   []map[string]string{{"client_id": "test-role", "sub": "test-entity"}},
	})

	actorToken := createJWTWithClaims(map[string]interface{}{
		"iss":       "test-issuer",
		"sub":       "test-entity",
		"aud":       "test",
		"client_id": "test-role",
	})

	// Perform token exchange with mixed scopes (profile has template, read/write don't)
	tokenReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/test-role",
		Storage:   storage,
		EntityID:  "test-entity",
		Data: map[string]interface{}{
			"subject_token": subjectToken,
			"actor_token":   actorToken,
			"audience":      "test-audience",
			"scope":         "profile read write",
		},
	}

	resp, err := b.HandleRequest(context.Background(), tokenReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "expected no error, got: %v", resp.Error())

	// Verify the access token
	accessToken, ok := resp.Data["access_token"].(string)
	require.True(t, ok, "expected access_token to be a string")
	require.NotEmpty(t, accessToken)

	// Parse the access token to verify claims
	parsedToken, err := jwt.ParseSigned(accessToken)
	require.NoError(t, err)

	var claims map[string]interface{}
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	require.NoError(t, err)

	// Verify the scope claim includes ALL requested scopes (templated and non-templated)
	assert.Equal(t, "profile read write", claims["scope"], "all requested scopes should be in scope claim")

	// Verify only the profile scope template was populated
	assert.Equal(t, "test@example.com", claims["email"], "expected email from profile scope template")

	// Verify read and write scopes didn't add any claims (they're just in the scope string)
	_, hasRead := claims["read"]
	_, hasWrite := claims["write"]
	assert.False(t, hasRead, "read scope should not add claims")
	assert.False(t, hasWrite, "write scope should not add claims")
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
		name     string
		setup    func(t *testing.T, b *oauthBackend, storage logical.Storage) (subjectToken, actorToken string)
		entityID string
		wantErr  bool
		errMsg   string
		check    func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "missing entity ID",
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
					},
				})

				// Create actor token
				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "test-client",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
				})

				return subjectToken, actorToken
			},
			entityID: "", // Empty entity ID to trigger error
			wantErr:  true,
			errMsg:   "no entity associated with the request's token",
		},
		{
			name:     "successful token exchange with act claim",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
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

				sub, ok := claims["sub"].(string)
				require.True(t, ok, "sub claim should be present")
				assert.Equal(t, "064a698a-4133-7443-b89d-aecd885aa3ee", sub)

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

				// Verify scope is included in act claim from actor token
				actScope, ok := act["scope"].(string)
				require.True(t, ok, "scope should be present in act claim")
				assert.Equal(t, "helloworld:read", actScope)

				// Verify nested act is not present
				require.NotContains(t, act, "act", "nested act claim should not be present")
			},
		},
		{
			name:     "successful token exchange with nested act claims",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
			setup: func(t *testing.T, b *oauthBackend, storage logical.Storage) (string, string) {
				// Create subject token with may_act claim and nested act claim
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
					"act": map[string]interface{}{
						"sub":       "a1b2c3d4-5678-90ab-cdef-1234567890ab",
						"client_id": "first-client",
					},
				})

				// Create actor token (without nested act claims)
				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "helloworld-agent",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
					"scope":     "helloworld:read",
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

				sub, ok := claims["sub"].(string)
				require.True(t, ok, "sub claim should be present")
				assert.Equal(t, "064a698a-4133-7443-b89d-aecd885aa3ee", sub)

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

				// Verify scope is included in act claim from actor token
				actScope, ok := act["scope"].(string)
				require.True(t, ok, "scope should be present in act claim")
				assert.Equal(t, "helloworld:read", actScope)

				// Verify nested act
				nestedAct, ok := act["act"].(map[string]interface{})
				require.True(t, ok, "nested act claim should be present")
				assert.Equal(t, "a1b2c3d4-5678-90ab-cdef-1234567890ab", nestedAct["sub"])
				assert.Equal(t, "first-client", nestedAct["client_id"])
			},
		},
		{
			name:     "successful token exchange with deeply nested act claims (3 levels)",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
			setup: func(t *testing.T, b *oauthBackend, storage logical.Storage) (string, string) {
				// Create subject token with 3 levels of nested act claims
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

				// Create actor token
				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "test-client",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"namespace": "root",
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

				sub, ok := claims["sub"].(string)
				require.True(t, ok, "sub claim should be present")
				assert.Equal(t, "064a698a-4133-7443-b89d-aecd885aa3ee", sub)

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
				&logical.Request{
					Storage:  storage,
					EntityID: tc.entityID,
				},
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

// TestPathTokenExchange tests the token exchange endpoint via HandleRequest
func TestPathTokenExchange(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, b logical.Backend, storage logical.Storage) (subjectToken, actorToken string)
		roleName string
		data     map[string]interface{}
		entityID string
		wantErr  bool
		errMsg   string
		check    func(t *testing.T, resp *logical.Response)
	}{
		{
			name: "missing subject_token parameter",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				return "", ""
			},
			data: map[string]interface{}{
				"role":        "test-role",
				"actor_token": "test-actor-token",
			},
			wantErr: true,
			errMsg:  "missing subject_token",
		},
		{
			name: "missing actor_token parameter",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				return "", ""
			},
			data: map[string]interface{}{
				"role":          "test-role",
				"subject_token": "test-subject-token",
			},
			wantErr: true,
			errMsg:  "missing actor_token",
		},
		{
			name: "role not found",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				// Create config
				config := &oauthConfig{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
				}
				entry, err := logical.StorageEntryJSON("config", config)
				require.NoError(t, err)
				err = storage.Put(context.Background(), entry)
				require.NoError(t, err)

				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "test-issuer",
					"sub":       "user123",
					"aud":       "test",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"may_act":   []map[string]string{{"client_id": "test-role", "sub": "entity-123"}},
				})

				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "test-issuer",
					"sub":       "entity-123",
					"aud":       "test",
					"client_id": "test-role",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
				})

				return subjectToken, actorToken
			},
			entityID: "entity-123",
			wantErr:  true,
			errMsg:   "role not found",
		},
		{
			name:     "successful token exchange via ReadOperation",
			roleName: "test-role",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				// Create config
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
					KeyID:     "test-key-id",
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

				// Create tokens
				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://localhost:8200/v1/identity/oidc/provider/test",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"client_id": "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"may_act": []map[string]string{
						{
							"client_id": "test-role",
							"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						},
					},
				})

				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "test-audience",
					"client_id": "test-role",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"scope":     "read:data",
				})

				return subjectToken, actorToken
			},
			data: map[string]interface{}{
				"role":     "test-role",
				"audience": "test-audience",
				"scope":    "read:data",
			},
			wantErr: false,
			check: func(t *testing.T, resp *logical.Response) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Data)

				// Verify response structure
				assert.Contains(t, resp.Data, "access_token")
				assert.Contains(t, resp.Data, "issued_token_type")
				assert.Contains(t, resp.Data, "token_type")
				assert.Contains(t, resp.Data, "expires_in")
				assert.Equal(t, "Bearer", resp.Data["token_type"])
				assert.Equal(t, tokenTypeAccessToken, resp.Data["issued_token_type"])

				// Parse and verify the access token
				accessToken := resp.Data["access_token"].(string)
				parsedToken, err := jwt.ParseSigned(accessToken)
				require.NoError(t, err)

				var claims map[string]interface{}
				err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
				require.NoError(t, err)

				// Verify claims
				assert.Equal(t, "test-audience", claims["aud"])
				assert.Equal(t, "test-role", claims["client_id"])
				assert.Equal(t, "read:data", claims["scope"])
				assert.Contains(t, claims, "act")

				// Verify scope is included in act claim from actor token
				act, ok := claims["act"].(map[string]interface{})
				require.True(t, ok, "act claim should be present")
				actScope, ok := act["scope"].(string)
				require.True(t, ok, "scope should be present in act claim")
				assert.Equal(t, "read:data", actScope)
			},
		},
		{
			name:     "successful token exchange with optional parameters",
			roleName: "test-role",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				// Create config
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
					KeyID:     "test-key-id",
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

				// Create tokens
				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://localhost:8200/v1/identity/oidc/provider/test",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"client_id": "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"may_act": []map[string]string{
						{
							"client_id": "test-role",
							"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						},
					},
				})

				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "default-audience",
					"client_id": "test-role",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
				})

				return subjectToken, actorToken
			},
			wantErr: false,
			check: func(t *testing.T, resp *logical.Response) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Data)
				assert.Contains(t, resp.Data, "access_token")
			},
		},
		{
			name:     "successful token exchange with custom client_id",
			roleName: "test-role",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				// Create config
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
					KeyID:     "test-key-id",
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

				// Create tokens with custom client_id
				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://localhost:8200/v1/identity/oidc/provider/test",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"client_id": "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"may_act": []map[string]string{
						{
							"client_id": "custom-client-id",
							"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						},
					},
				})

				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "test-audience",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"scope":     "read:data",
				})

				return subjectToken, actorToken
			},
			data: map[string]interface{}{
				"role":      "test-role",
				"client_id": "custom-client-id",
				"audience":  "test-audience",
				"scope":     "read:data",
			},
			wantErr: false,
			check: func(t *testing.T, resp *logical.Response) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Data)

				// Verify response structure
				assert.Contains(t, resp.Data, "access_token")
				assert.Contains(t, resp.Data, "issued_token_type")
				assert.Contains(t, resp.Data, "token_type")
				assert.Contains(t, resp.Data, "expires_in")
				assert.Equal(t, "Bearer", resp.Data["token_type"])
				assert.Equal(t, tokenTypeAccessToken, resp.Data["issued_token_type"])

				// Parse and verify the access token
				accessToken := resp.Data["access_token"].(string)
				parsedToken, err := jwt.ParseSigned(accessToken)
				require.NoError(t, err)

				var claims map[string]interface{}
				err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
				require.NoError(t, err)

				// Verify that custom client_id is used instead of role name
				assert.Equal(t, "custom-client-id", claims["client_id"], "client_id should be the custom value, not the role name")
				assert.Equal(t, "test-audience", claims["aud"])
				assert.Equal(t, "read:data", claims["scope"])
				assert.Contains(t, claims, "act")

				// Verify scope is included in act claim from actor token
				act, ok := claims["act"].(map[string]interface{})
				require.True(t, ok, "act claim should be present")
				actScope, ok := act["scope"].(string)
				require.True(t, ok, "scope should be present in act claim")
				assert.Equal(t, "read:data", actScope)

				// Verify actor claim also has the custom client_id
				actClaim := claims["act"].(map[string]interface{})
				assert.Equal(t, "custom-client-id", actClaim["client_id"])
			},
		},
		{
			name:     "token exchange defaults to role name when client_id not provided",
			roleName: "test-role",
			entityID: "52b1da4c-0a60-f23a-3384-1d5837af487e",
			setup: func(t *testing.T, b logical.Backend, storage logical.Storage) (string, string) {
				// Create config
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
					KeyID:     "test-key-id",
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

				// Create tokens - note client_id in may_act matches role name
				subjectToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://localhost:8200/v1/identity/oidc/provider/test",
					"sub":       "064a698a-4133-7443-b89d-aecd885aa3ee",
					"aud":       "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"client_id": "lF7iYit6FaxpfyOMICqJLzDrQsCYQYsZ",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"may_act": []map[string]string{
						{
							"client_id": "test-role",
							"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
						},
					},
				})

				actorToken := createJWTWithClaims(map[string]interface{}{
					"iss":       "http://127.0.0.1:8200/v1/identity/oidc",
					"sub":       "52b1da4c-0a60-f23a-3384-1d5837af487e",
					"aud":       "test-audience",
					"client_id": "test-client",
					"exp":       time.Now().Add(1 * time.Hour).Unix(),
					"scope":     "read:data",
				})

				return subjectToken, actorToken
			},
			data: map[string]interface{}{
				"role":     "test-role",
				"audience": "test-audience",
				"scope":    "read:data",
				// Note: client_id is NOT provided, should default to role name
			},
			wantErr: false,
			check: func(t *testing.T, resp *logical.Response) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Data)

				// Parse and verify the access token
				accessToken := resp.Data["access_token"].(string)
				parsedToken, err := jwt.ParseSigned(accessToken)
				require.NoError(t, err)

				var claims map[string]interface{}
				err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
				require.NoError(t, err)

				// Verify that client_id defaults to role name when not provided
				assert.Equal(t, "test-role", claims["client_id"], "client_id should default to role name when not provided")

				// Verify actor claim also has the role name as client_id
				actClaim := claims["act"].(map[string]interface{})
				assert.Equal(t, "test-role", actClaim["client_id"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t)

			// Setup test data
			subjectToken, actorToken := tc.setup(t, b, storage)

			// Build data map with tokens
			data := tc.data
			if data == nil {
				data = make(map[string]interface{})
			}

			// Add tokens to data if they were created
			if subjectToken != "" {
				data["subject_token"] = subjectToken
			}
			if actorToken != "" {
				data["actor_token"] = actorToken
			}

			// Use roleName from test case, default to "test-role" if not specified
			roleName := tc.roleName
			if roleName == "" {
				roleName = "test-role"
			}

			// Make the request using ReadOperation (as changed in path_token.go)
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "token/" + roleName,
				Data:      data,
				Storage:   storage,
				EntityID:  tc.entityID,
			})

			if tc.wantErr {
				if err != nil {
					assert.Contains(t, err.Error(), tc.errMsg)
				} else {
					require.NotNil(t, resp)
					require.True(t, resp.IsError(), "expected error response")
					if tc.errMsg != "" {
						assert.Contains(t, resp.Error().Error(), tc.errMsg)
					}
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.False(t, resp.IsError(), "unexpected error: %v", resp.Error())
				if tc.check != nil {
					tc.check(t, resp)
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
