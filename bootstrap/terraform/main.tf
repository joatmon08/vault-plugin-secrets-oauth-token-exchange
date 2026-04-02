terraform {
  required_version = ">= 1.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "vault" {
  # Configuration will be taken from VAULT_ADDR and VAULT_TOKEN environment variables
}

# Create an OIDC provider for subject tokens
resource "vault_identity_oidc_key" "key" {
  name               = "oauth-token-exchange"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_scope" "helloworld" {
  name        = "helloworld-read"
  template    = "{\"scopes\":[\"helloworld:read\"]}"
  description = "Helloworld read scope"
}

resource "vault_identity_oidc_provider" "provider" {
  name          = "test"
  https_enabled = false
  issuer_host   = "localhost:8200"
  allowed_client_ids = [
    vault_identity_oidc_client.client.client_id
  ]
  scopes_supported = [vault_identity_oidc_scope.helloworld.name]
}

resource "vault_identity_oidc_client" "client" {
  name = "test"
  key  = vault_identity_oidc_key.key.name
  redirect_uris = [
    "http://localhost:8200/v1/oauth-token-exchange/callback"
  ]
  assignments      = []
  id_token_ttl     = 2400
  access_token_ttl = 7200
}

# Output the client credentials
output "oidc_client_id" {
  value       = vault_identity_oidc_client.client.client_id
  description = "OIDC Client ID for OAuth token exchange"
}

output "oidc_client_secret" {
  value       = vault_identity_oidc_client.client.client_secret
  description = "OIDC Client Secret for OAuth token exchange"
  sensitive   = true
}

output "oidc_provider_issuer" {
  value       = vault_identity_oidc_provider.provider.issuer
  description = "OIDC Provider Issuer URL"
}