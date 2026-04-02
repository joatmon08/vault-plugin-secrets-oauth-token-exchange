# vault-plugin-secrets-oauth-token-exchange

Vault secret engine plugin for OAuth 2.0 Token Exchange (RFC 8693)

## Overview

This Vault secrets engine implements [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html). It enables secure token exchange workflows by:

- Using Vault as an OIDC provider to obtain subject tokens via the authorization code flow
- Integrating with Vault's identity secrets for actor tokens in delegation scenarios
- Performing RFC 8693 compliant token exchange with external OAuth providers

## Features

- **OIDC Authorization Code Flow**: Obtain subject tokens through Vault's OIDC provider
- **Actor Token Support**: Use Vault identity tokens for delegation scenarios
- **RFC 8693 Compliance**: Full implementation of OAuth 2.0 Token Exchange specification
- **Role-based Configuration**: Define multiple roles with different token exchange endpoints and parameters

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

2. Register the plugin with Vault:
```bash
vault plugin register \
    -sha256=$(shasum -a 256 bin/vault-plugin-secrets-oauth-token-exchange | awk '{print $1}') \
    -command="vault-plugin-secrets-oauth-token-exchange" \
    secret \
    vault-plugin-secrets-oauth-token-exchange
```

3. Enable the secrets engine:
```bash
vault secrets enable -path=oauth-token-exchange vault-plugin-secrets-oauth-token-exchange
```

## Configuration

### Configure OAuth Provider

```bash
vault write oauth-token-exchange/config \
    client_id="your-client-id" \
    client_secret="your-client-secret" \
    auth_url="https://vault.example.com/ui/vault/identity/oidc/provider/oauth-provider/authorize" \
    token_url="https://vault.example.com/v1/identity/oidc/provider/oauth-provider/token" \
    redirect_url="http://localhost:8200/v1/oauth-token-exchange/callback" \
    issuer_url="https://vault.example.com/v1/identity/oidc/provider/oauth-provider" \
    scopes="openid,profile"
```

### Create a Role

```bash
vault write oauth-token-exchange/role/my-role \
    token_exchange_url="https://oauth-provider.example.com/token" \
    audience="https://api.example.com" \
    scope="read write" \
    ttl=3600 \
    max_ttl=86400
```

## Usage

### 1. Get Authorization URL

```bash
vault read oauth-token-exchange/authorize/my-role
```

This returns an authorization URL. Direct users to this URL to authenticate.

### 2. Handle Callback

After user authentication, the OAuth provider redirects to the callback URL with an authorization code. Exchange it for tokens:

```bash
vault write oauth-token-exchange/callback \
    code="authorization-code-from-callback" \
    state="state-from-authorize-response"
```

This returns an access token (subject_token).

### 3. Perform Token Exchange

Use the subject token to exchange for a new token:

```bash
vault write oauth-token-exchange/token/my-role \
    subject_token="access-token-from-callback"
```

For delegation scenarios with an actor token:

```bash
vault write oauth-token-exchange/token/my-role \
    subject_token="access-token-from-callback" \
    actor_token="actor-token-from-identity"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Vault Plugin                              │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Config     │  │    Roles     │  │    Token     │     │
│  │   Endpoint   │  │   Endpoint   │  │   Exchange   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                  │                  │             │
│         └──────────────────┴──────────────────┘             │
│                            │                                │
└────────────────────────────┼────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
        ┌───────▼────────┐       ┌───────▼────────┐
        │  Vault OIDC    │       │  External      │
        │  Provider      │       │  OAuth         │
        │  (Subject      │       │  Provider      │
        │   Token)       │       │  (Token        │
        └────────────────┘       │   Exchange)    │
                                 └────────────────┘
```

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
