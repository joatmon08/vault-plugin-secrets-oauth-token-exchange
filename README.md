# vault-plugin-secrets-oauth-token-exchange

Vault secrets engine plugin for OAuth 2.0 Token Exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html))

## Overview

This Vault secrets engine implements [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html), enabling secure token exchange and delegation workflows. **This plugin acts as the RFC 8693 token exchange endpoint itself**, issuing signed JWT access tokens based on subject and actor tokens.

### How It Works

The secrets engine performs token exchange by:

1. **Accepting subject tokens** - JWT tokens representing the primary identity (e.g., from Vault's OIDC provider)
2. **Accepting actor tokens** - JWT tokens representing the delegated identity (e.g., from Vault's identity secrets)
3. **Verifying permissions** - Checking that the actor has permission to act on behalf of the subject via the `may_act` claim
4. **Issuing access tokens** - Generating RFC 8693-compliant signed JWT access tokens with actor delegation chains

### RFC 8693 Implementation

This plugin implements the OAuth 2.0 Token Exchange specification (RFC 8693) with the following key features:

- **Grant Type**: Uses `urn:ietf:params:oauth:grant-type:token-exchange` as specified in RFC 8693 Section 2.1
- **Token Types**: Issues `urn:ietf:params:oauth:token-type:access_token` tokens (RFC 8693 Section 3)
- **Actor Delegation**: Supports delegation scenarios with the `act` (actor) claim for representing delegation chains (RFC 8693 Section 4.1)
- **Subject Token Verification**: Validates subject tokens using JWKS for signature verification
- **Actor Token Verification**: Validates actor tokens using JWKS for signature verification
- **Permission Model**: Uses the `may_act` claim in subject tokens to authorize which actors can perform delegation

## Features

- **RFC 8693 Token Exchange Endpoint**: Acts as a compliant token exchange service
- **JWT Signing**: Issues signed JWT access tokens using configurable signing keys
- **Actor Delegation Chains**: Supports multi-level delegation with the `act` claim
- **JWKS Verification**: Verifies subject and actor token signatures using JWKS endpoints
- **Role-based Configuration**: Define multiple roles with different issuers, keys, and TTL settings
- **Flexible Key Management**: Support for multiple signing keys with allowed client ID restrictions

## Building

```bash
# Build the plugin
make dev

# Run tests
go test -v ./...
```

## Installation

1. Build the plugin binary:
```bash
make dev
```

2. Calculate the SHA256 checksum and register the plugin with Vault:
```bash
SHA256=$(shasum -a 256 bin/vault-plugin-secrets-oauth-token-exchange | cut -d ' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-oauth-token-exchange
```

3. Enable the secrets engine at your desired path:
```bash
vault secrets enable -path=sts vault-plugin-secrets-oauth-token-exchange
```

4. (Optional) Configure audit logging for sensitive fields:
```bash
vault secrets tune -audit-non-hmac-request-keys=scope \
    -audit-non-hmac-request-keys=subject \
    -audit-non-hmac-request-keys=audience \
    sts
```

## Configuration

The secrets engine requires configuration in four steps: config, keys, roles, and optionally scopes.

### Step 1: Configure the Secrets Engine

Configure the OAuth client credentials and subject token verification:

```bash
vault write sts/config \
    client_id="your-oidc-client-id" \
    client_secret="your-oidc-client-secret" \
    subject_token_jwks_uri="http://localhost:8200/v1/identity/oidc/provider/test/.well-known/keys"
```

**Parameters:**
- `client_id` (required): OAuth 2.0 client ID for the OIDC provider
- `client_secret` (required): OAuth 2.0 client secret for the OIDC provider
- `subject_token_jwks_uri` (optional): JWKS URI for verifying subject token signatures

### Step 2: Create a Signing Key

Create a signing key that will be used to sign the issued access tokens:

```bash
vault write sts/key/test \
    allowed_client_ids="*"
```

**Parameters:**
- `allowed_client_ids` (required): List of client IDs allowed to use this key (use `"*"` for all clients)

The key is automatically generated with a rotation period and verification TTL.

### Step 3: Create Roles

Create one or more roles that define how tokens are issued:

```bash
vault write sts/role/test-client \
    key="test" \
    issuer="http://localhost:8200/v1/identity/oidc/provider/test" \
    actor_token_jwks_uri="http://localhost:8200/v1/identity/oidc/.well-known/keys"
```

**Parameters:**
- `key` (required): Name of the signing key to use for this role
- `issuer` (optional): Issuer (iss) claim for tokens issued by this role. If not provided, defaults to the mount path.
- `ttl` (optional): Default TTL for tokens issued by this role (default: 3600 seconds)
- `max_ttl` (optional): Maximum TTL for tokens issued by this role (default: 86400 seconds)
- `actor_token_jwks_uri` (optional): JWKS URI for verifying actor token signatures
- `scopes_supported` (optional): Comma-separated list of scope names that this role supports

### Step 4: Create Scopes (Optional)

Scopes allow you to add custom claims to issued tokens based on entity and group metadata using templates:

```bash
vault write sts/scope/custom-claims \
    template='{"department": {{identity.entity.metadata.department}}, "roles": {{identity.entity.metadata.roles}}}' \
    description="Custom claims for department and roles"
```

**Parameters:**
- `template` (required): Template string using identity templating language. Must produce valid JSON and cannot use reserved claim names (iss, sub, aud, exp, iat, client_id, act)
- `description` (optional): Description of the scope

The template can access entity and group metadata to populate custom claims in the issued tokens. Templates can be provided as JSON strings or base64-encoded.

## Usage

### Permission Model: The `may_act` Claim

The plugin uses the `may_act` claim in subject tokens to control delegation permissions. This claim specifies which actors are authorized to act on behalf of the subject.

**Subject Token Example:**
```json
{
  "iss": "http://localhost:8200/v1/identity/oidc/provider/default",
  "sub": "user-123",
  "aud": "my-app",
  "may_act": [
    {
      "client_id": "service-a",
      "sub": "entity-456"
    },
    {
      "client_id": "service-b",
      "sub": "entity-789"
    }
  ]
}
```

The token exchange will only succeed if:
1. The requesting entity's ID matches one of the `sub` values in `may_act`
2. The `client_id` in the request matches the corresponding `client_id` in `may_act`

### Performing Token Exchange (RFC 8693)

To exchange tokens, you need:
1. A **subject token** - JWT representing the primary identity (obtained from an OIDC provider)
2. An **actor token** - JWT representing the delegated identity (obtained from Vault identity tokens)

The subject token must contain a `may_act` claim that authorizes the actor to perform delegation.

#### Example: Token Exchange Request

```bash
vault read sts/token/test-client \
    subject_token="$SUBJECT_TOKEN" \
    actor_token="$ACTOR_TOKEN" \
    audience="helloworld-server" \
    scope="helloworld:read"
```

**Parameters:**
- `subject_token` (required): JWT token representing the primary identity
- `actor_token` (required): JWT token representing the delegated identity
- `audience` (optional): Target audience for the issued token
- `scope` (optional): Requested scope for the issued token
- `client_id` (optional): Client ID to use (defaults to role name)

#### Response

The endpoint returns an RFC 8693-compliant token response:

```json
{
  "access_token": "eyJhbGc...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "expires_in": 3600
}
```

The `access_token` is a signed JWT containing:
- `iss`: Issuer from the role configuration
- `sub`: Subject from the subject token
- `aud`: Audience specified in the request
- `client_id`: Client ID from the request
- `act`: Actor claim containing the delegation chain (RFC 8693 Section 4.1)
    - `sub`: Vault entity ID based on the role
    - `client_id`: Client ID from the actor token
    - `scope`: Scope specified in the request
- `scope`: Scope specified in the request
- `exp`, `iat`: Token expiry and issued-at timestamps

### Multi-Level Delegation

The plugin supports multi-level delegation chains. When a subject token already contains an `act` claim (representing a previous delegation), that nested delegation chain is preserved in the newly issued access token:

```bash
# First exchange: subject + actor1 → token1
vault read sts/token/test-client \
    subject_token="$SUBJECT_TOKEN" \
    actor_token="$ACTOR_TOKEN_1" \
    audience="service-a" \
    scope="write"

# Second exchange: subject_with_act + actor2 → token2 (nested delegation)
# The subject token here already contains an 'act' claim from a previous exchange
vault read sts/token/second-client \
    subject_token="$SUBJECT_TOKEN_WITH_ACT" \
    actor_token="$ACTOR_TOKEN_2" \
    audience="service-b" \
    scope="read"
```

**Important**: The nested `act` claim in the issued token comes from the **subject token**, not the actor token. If the subject token contains an `act` claim, it will be nested within the new actor claim in the issued token, creating a delegation chain.

### OpenID Connect Discovery

The plugin provides an OpenID Connect Discovery endpoint at `.well-known/openid-configuration` that returns metadata about the token exchange service. This endpoint is publicly accessible and follows the [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) specification.

**Example:**
```bash
# Retrieve the discovery document
curl http://localhost:8200/v1/sts/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "http://localhost:8200/v1/identity/oidc/provider/default",
  "jwks_uri": "http://localhost:8200/v1/sts/.well-known/keys",
  "token_endpoint": "http://localhost:8200/v1/sts/token",
  "response_types_supported": ["token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": [
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "EdDSA"
  ],
  "grant_types_supported": [
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ]
}
```

The discovery document allows OAuth clients and resource servers to automatically discover the configuration of the token exchange service, including the JWKS endpoint for retrieving public keys.

### JWKS Endpoints

The plugin provides and uses JWKS (JSON Web Key Set) endpoints:

- **Public JWKS Endpoint**: Available at `.well-known/keys`
  - Returns the public keys used to sign tokens issued by this plugin
  - Publicly accessible for token verification by resource servers
  - Example: `http://localhost:8200/v1/sts/.well-known/keys`

- **Subject Token JWKS**: Configured in `sts/config` via `subject_token_jwks_uri`
  - Used to verify the signature of subject tokens
  - Example: `http://localhost:8200/v1/identity/oidc/provider/default/.well-known/keys`

- **Actor Token JWKS**: Configured per-role via `actor_token_jwks_uri`
  - Used to verify the signature of actor tokens
  - Example: `http://localhost:8200/v1/identity/oidc/.well-known/keys`

The plugin fetches public keys from the configured JWKS endpoints to verify JWT signatures, ensuring tokens are authentic and haven't been tampered with. Resource servers can use the plugin's public JWKS endpoint to verify tokens issued by this token exchange service.

## Architecture

This secrets engine acts as an RFC 8693-compliant token exchange endpoint:

```
┌─────────────────────────────────────────────────────────────────┐
│                     External Systems                             │
│                                                                  │
│  ┌──────────────────┐              ┌──────────────────┐        │
│  │  Vault OIDC      │              │  Vault Identity  │        │
│  │  Provider        │              │  Secrets         │        │
│  │                  │              │                  │        │
│  │ Issues subject   │              │ Issues actor     │        │
│  │ tokens (JWT)     │              │ tokens (JWT)     │        │
│  └────────┬─────────┘              └────────┬─────────┘        │
│           │                                 │                   │
└───────────┼─────────────────────────────────┼───────────────────┘
            │                                 │
            │ subject_token                   │ actor_token
            │                                 │
            └─────────────┬───────────────────┘
                          │
                          ▼
            ┌─────────────────────────────────────────┐
            │  Vault OAuth Token Exchange Plugin      │
            │  (RFC 8693 Token Exchange Endpoint)     │
            │                                          │
            │  1. Verify subject token (JWKS)         │
            │  2. Verify actor token (JWKS)           │
            │  3. Check may_act permissions           │
            │  4. Generate access token (JWT)         │
            │  5. Sign with configured key            │
            └─────────────┬───────────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │ RFC 8693      │
                  │ Access Token  │
                  │ (Signed JWT)  │
                  └───────────────┘
```

Note that you can use any OIDC provider for the subject token, as long as it includes a `may_act` claim.
Similarly, you can use other providers for the actor token as long as it includes
a `client_id` and `sub` claim.

### Token Flow

1. **Subject Token**: Obtained from an OIDC provider (e.g., Vault's identity OIDC provider)
   - Contains identity information and `may_act` claim listing authorized actors
   
2. **Actor Token**: Obtained from Vault's identity secrets or a previous token exchange
   - Represents the entity performing the delegation
   
3. **Access Token**: Issued by this plugin
   - RFC 8693-compliant JWT with `act` claim showing delegation chain
   - Signed using the configured signing key
   - Can be used as an actor token in subsequent exchanges (multi-level delegation)

## Complete Example Workflow

Here's a complete example showing how to set up and use the plugin:

### 1. Setup and Configuration

```bash
# Enable the secrets engine
vault secrets enable -path=sts vault-plugin-secrets-oauth-token-exchange

# Configure with OIDC client credentials
vault write sts/config \
    client_id="my-oidc-client" \
    client_secret="my-oidc-secret" \
    subject_token_jwks_uri="http://localhost:8200/v1/identity/oidc/provider/default/.well-known/keys"

# Create a signing key
vault write sts/key/production \
    allowed_client_ids="*"

# Create a role for your application
vault write sts/role/my-app \
    key="production" \
    issuer="http://localhost:8200/v1/identity/oidc/provider/default" \
    actor_token_jwks_uri="http://localhost:8200/v1/identity/oidc/.well-known/keys" \
    ttl=3600 \
    max_ttl=86400

# (Optional) Create a scope for custom claims
vault write sts/scope/user-metadata \
    template='{"department": {{identity.entity.metadata.department}}}' \
    description="Include user department in tokens"

# Update role to support the scope
vault write sts/role/my-app \
    key="production" \
    issuer="http://localhost:8200/v1/identity/oidc/provider/default" \
    actor_token_jwks_uri="http://localhost:8200/v1/identity/oidc/.well-known/keys" \
    scopes_supported="user-metadata" \
    ttl=3600 \
    max_ttl=86400
```

### 2. Obtain Tokens

```bash
# Get a subject token from your OIDC provider
# (This example assumes you have a subject token with may_act claim)
SUBJECT_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Get an actor token from Vault identity
ACTOR_TOKEN=$(vault read -format=json identity/oidc/token/my-entity | jq -r .data.token)
```

### 3. Perform Token Exchange

```bash
# Exchange tokens to get an RFC 8693 access token
vault read sts/token/my-app \
    subject_token="$SUBJECT_TOKEN" \
    actor_token="$ACTOR_TOKEN" \
    audience="my-api-server" \
    scope="user-metadata"
```

### 4. Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMyJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgyMDAvdjEvaWRlbnRpdHkvb2lkYy9wcm92aWRlci9kZWZhdWx0Iiwic3ViIjoidXNlci0xMjMiLCJhdWQiOiJteS1hcGktc2VydmVyIiwiZXhwIjoxNzEyNjg0NDAwLCJpYXQiOjE3MTI2ODA4MDAsImNsaWVudF9pZCI6Im15LWFwcCIsImFjdCI6eyJzdWIiOiJlbnRpdHktNDU2IiwiY2xpZW50X2lkIjoibXktYXBwIn0sInNjb3BlIjoicmVhZDpkYXRhIHdyaXRlOmRhdGEifQ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "expires_in": 3600
}
```

The issued access token contains:
- **iss**: `http://localhost:8200/v1/identity/oidc/provider/default`
- **sub**: `user-123` (from subject token)
- **aud**: `my-api-server` (from request)
- **client_id**: `my-app` (from request/role)
- **act**: `{"sub": "entity-456", "client_id": "my-app"}` (actor delegation)
- **scope**: `read:data write:data` (from request)

## Development

### Prerequisites

- Go 1.22 or later
- Vault 1.10 or later
- Terraform (for bootstrap environment)

### Setup Development Environment

```bash
# Initialize Terraform for OIDC provider setup
cd bootstrap/terraform
terraform init
terraform apply

# Build and configure the plugin
make configure
```

### Testing

```bash
# Run unit tests
go test -v ./...

# Run with coverage
go test -cover ./...
```

## License

Mozilla Public License 2.0

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [Vault Plugin Development](https://developer.hashicorp.com/vault/docs/plugins)
- [Vault Custom Secrets Engine Tutorial](https://developer.hashicorp.com/vault/tutorials/custom-secrets-engine)
