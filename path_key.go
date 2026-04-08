package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	keyStoragePath = "key/"
)

// Supported signing algorithms
const (
	AlgRS256 = string(jose.RS256)
	AlgRS384 = string(jose.RS384)
	AlgRS512 = string(jose.RS512)
	AlgES256 = string(jose.ES256)
	AlgES384 = string(jose.ES384)
	AlgES512 = string(jose.ES512)
)

var supportedAlgs = []string{
	AlgRS256,
	AlgRS384,
	AlgRS512,
	AlgES256,
	AlgES384,
	AlgES512,
}

type expireableKey struct {
	KeyID    string    `json:"key_id"`
	ExpireAt time.Time `json:"expire_at"`
}

// namedKey represents a named signing key
type namedKey struct {
	name             string
	Algorithm        string           `json:"algorithm"`
	VerificationTTL  time.Duration    `json:"verification_ttl"`
	RotationPeriod   time.Duration    `json:"rotation_period"`
	KeyRing          []*expireableKey `json:"key_ring"`
	SigningKey       *jose.JSONWebKey `json:"signing_key"`
	NextSigningKey   *jose.JSONWebKey `json:"next_signing_key"`
	NextRotation     time.Time        `json:"next_rotation"`
	AllowedClientIDs []string         `json:"allowed_client_ids"`
}

// pathKey extends the Vault API with key management endpoints
func pathKey(b *oauthBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "key/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key",
				},
				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: "How often to generate a new keypair.",
					Default:     86400, // 24 hours
				},
				"verification_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Controls how long the public portion of a key will be available for verification after being rotated.",
					Default:     86400, // 24 hours
				},
				"algorithm": {
					Type:        framework.TypeString,
					Description: "Signing algorithm to use. This will default to RS256.",
					Default:     AlgRS256,
				},
				"allowed_client_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Comma separated string or array of role client ids allowed to use this key for signing. If empty no roles are allowed. If \"*\" all roles are allowed.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeyCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeyCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeyRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathKeyDelete,
				},
			},
			ExistenceCheck:  b.pathKeyExistenceCheck,
			HelpSynopsis:    "CRUD operations for signing keys.",
			HelpDescription: "Create, Read, Update, and Delete named signing keys.",
		},
		{
			Pattern: "key/" + framework.GenericNameRegex("name") + "/rotate/?$",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key",
				},
				"verification_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Controls how long the public portion of a key will be available for verification after being rotated. Setting verification_ttl here will override the verification_ttl set on the key.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeyRotate,
				},
			},
			HelpSynopsis:    "Rotate a named key.",
			HelpDescription: "Manually rotate a named key. Rotating a named key will cause a new underlying signing key to be generated. The public portion of the underlying rotated signing key will continue to live for the verification_ttl duration.",
		},
		{
			Pattern: "key/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeyList,
				},
			},
			HelpSynopsis:    "List signing keys",
			HelpDescription: "List all named signing keys",
		},
	}
}

// pathKeyExistenceCheck checks if a key exists
func (b *oauthBackend) pathKeyExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	if name == "" {
		return false, nil
	}

	entry, err := req.Storage.Get(ctx, keyStoragePath+name)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

// pathKeyCreateUpdate creates or updates a signing key
func (b *oauthBackend) pathKeyCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing key name"), nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	var key namedKey
	if req.Operation == logical.UpdateOperation {
		entry, err := req.Storage.Get(ctx, keyStoragePath+name)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			if err := entry.DecodeJSON(&key); err != nil {
				return nil, err
			}
		}
	}

	if rotationPeriodRaw, ok := data.GetOk("rotation_period"); ok {
		key.RotationPeriod = time.Duration(rotationPeriodRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		key.RotationPeriod = time.Duration(data.Get("rotation_period").(int)) * time.Second
	}

	if key.RotationPeriod < 1*time.Minute {
		return logical.ErrorResponse("rotation_period must be at least one minute"), nil
	}

	if verificationTTLRaw, ok := data.GetOk("verification_ttl"); ok {
		key.VerificationTTL = time.Duration(verificationTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		key.VerificationTTL = time.Duration(data.Get("verification_ttl").(int)) * time.Second
	}

	if key.VerificationTTL > 10*key.RotationPeriod {
		return logical.ErrorResponse("verification_ttl cannot be longer than 10x rotation_period"), nil
	}

	if algorithmRaw, ok := data.GetOk("algorithm"); ok {
		key.Algorithm = algorithmRaw.(string)
	} else if req.Operation == logical.CreateOperation {
		key.Algorithm = data.Get("algorithm").(string)
	}

	if !isValidAlgorithm(key.Algorithm) {
		return logical.ErrorResponse(fmt.Sprintf("invalid algorithm %q, must be one of: %v", key.Algorithm, supportedAlgs)), nil
	}

	if allowedClientIDsRaw, ok := data.GetOk("allowed_client_ids"); ok {
		key.AllowedClientIDs = allowedClientIDsRaw.([]string)
	} else if req.Operation == logical.CreateOperation {
		key.AllowedClientIDs = data.Get("allowed_client_ids").([]string)
	}

	// Generate initial signing key if this is a new key
	if req.Operation == logical.CreateOperation {
		key.name = name

		signingKey, err := generateJSONWebKey(key.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		key.SigningKey = signingKey
		key.NextRotation = time.Now().Add(key.RotationPeriod)
		key.KeyRing = []*expireableKey{}

		// Store the public key for JWKS endpoint
		if err := storePublicKey(ctx, req.Storage, signingKey); err != nil {
			return nil, fmt.Errorf("failed to store public key: %w", err)
		}
	}

	// Store the key
	entry, err := logical.StorageEntryJSON(keyStoragePath+name, &key)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":               name,
			"algorithm":          key.Algorithm,
			"rotation_period":    int64(key.RotationPeriod / time.Second),
			"verification_ttl":   int64(key.VerificationTTL / time.Second),
			"allowed_client_ids": key.AllowedClientIDs,
			"next_rotation":      key.NextRotation.Format(time.RFC3339),
		},
	}, nil
}

// pathKeyRead reads a signing key
func (b *oauthBackend) pathKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing key name"), nil
	}

	entry, err := req.Storage.Get(ctx, keyStoragePath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var key namedKey
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, err
	}

	respData := map[string]interface{}{
		"name":               name,
		"algorithm":          key.Algorithm,
		"rotation_period":    int64(key.RotationPeriod / time.Second),
		"verification_ttl":   int64(key.VerificationTTL / time.Second),
		"allowed_client_ids": key.AllowedClientIDs,
		"next_rotation":      key.NextRotation.Format(time.RFC3339),
	}

	// Include key ID if signing key exists
	if key.SigningKey != nil {
		respData["key_id"] = key.SigningKey.KeyID
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

// pathKeyDelete deletes a signing key
func (b *oauthBackend) pathKeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing key name"), nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	if err := req.Storage.Delete(ctx, keyStoragePath+name); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathKeyList lists all signing keys
func (b *oauthBackend) pathKeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, keyStoragePath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(keys), nil
}

// pathKeyRotate rotates a signing key
func (b *oauthBackend) pathKeyRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing key name"), nil
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	entry, err := req.Storage.Get(ctx, keyStoragePath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("key not found"), nil
	}

	var key namedKey
	if err := entry.DecodeJSON(&key); err != nil {
		return nil, err
	}

	// Override verification TTL if provided
	if verificationTTLRaw, ok := data.GetOk("verification_ttl"); ok {
		key.VerificationTTL = time.Duration(verificationTTLRaw.(int)) * time.Second
	}

	// Perform rotation
	if err := rotateNamedKey(ctx, req.Storage, name, &key); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":             name,
			"algorithm":        key.Algorithm,
			"key_id":           key.SigningKey.KeyID,
			"rotation_period":  int64(key.RotationPeriod / time.Second),
			"verification_ttl": int64(key.VerificationTTL / time.Second),
			"next_rotation":    key.NextRotation.Format(time.RFC3339),
		},
	}, nil
}

// Helper functions

func isValidAlgorithm(alg string) bool {
	for _, supported := range supportedAlgs {
		if alg == supported {
			return true
		}
	}
	return false
}

func generateJSONWebKey(algorithm string) (*jose.JSONWebKey, error) {
	var key interface{}
	var err error

	switch algorithm {
	case AlgRS256, AlgRS384, AlgRS512:
		// Generate RSA key
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

	case AlgES256:
		// Generate ECDSA key with P-256 curve
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

	case AlgES384:
		// Generate ECDSA key with P-384 curve
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}

	case AlgES512:
		// Generate ECDSA key with P-521 curve
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Create JSONWebKey
	jwk := &jose.JSONWebKey{
		Key:       key,
		KeyID:     generateKeyID(),
		Algorithm: algorithm,
		Use:       "sig",
	}

	return jwk, nil
}

func generateKeyID() string {
	// Generate a random key ID
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func rotateNamedKey(ctx context.Context, s logical.Storage, name string, key *namedKey) error {
	// Move current signing key to next signing key
	if key.SigningKey != nil {
		key.NextSigningKey = key.SigningKey

		// Store the public key for JWKS endpoint
		if err := storePublicKey(ctx, s, key.SigningKey); err != nil {
			return fmt.Errorf("failed to store public key: %w", err)
		}

		// Add to key ring with expiration
		expireAt := time.Now().Add(key.VerificationTTL)
		key.KeyRing = append(key.KeyRing, &expireableKey{
			KeyID:    key.SigningKey.KeyID,
			ExpireAt: expireAt,
		})
	}

	// Generate new signing key
	newKey, err := generateJSONWebKey(key.Algorithm)
	if err != nil {
		return fmt.Errorf("failed to generate new signing key: %w", err)
	}
	key.SigningKey = newKey

	// Store the new public key for JWKS endpoint
	if err := storePublicKey(ctx, s, newKey); err != nil {
		return fmt.Errorf("failed to store new public key: %w", err)
	}

	// Update next rotation time
	key.NextRotation = time.Now().Add(key.RotationPeriod)

	// Prune expired keys from key ring and delete their public keys
	now := time.Now()
	validKeys := make([]*expireableKey, 0)
	for _, k := range key.KeyRing {
		if k.ExpireAt.After(now) {
			validKeys = append(validKeys, k)
		} else {
			// Delete expired public key
			if err := deletePublicKey(ctx, s, k.KeyID); err != nil {
				// Log but don't fail rotation
				continue
			}
		}
	}
	key.KeyRing = validKeys

	// Store updated key
	entry, err := logical.StorageEntryJSON(keyStoragePath+name, key)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

// storePublicKey stores the public portion of a key for JWKS retrieval
func storePublicKey(ctx context.Context, s logical.Storage, jwk *jose.JSONWebKey) error {
	if jwk == nil {
		return fmt.Errorf("cannot store nil key")
	}

	publicKey := jwk.Public()
	entry, err := logical.StorageEntryJSON("public_key/"+jwk.KeyID, &publicKey)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

// deletePublicKey removes a public key from storage
func deletePublicKey(ctx context.Context, s logical.Storage, keyID string) error {
	return s.Delete(ctx, "public_key/"+keyID)
}

// Made with Bob
