terraform {
  required_version = ">= 1.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}

provider "vault" {
  # Configuration will be taken from VAULT_ADDR and VAULT_TOKEN environment variables
}

# Set up the Vault identity tokens for generating actor tokens
# Implies a unique client identity tied to each role
# Actor tokens have the schema:
# {
#   "aud": "test-client",
#   "client_id": "test-client",
#   "exp": 1775315436,
#   "iat": 1775229036,
#   "iss": "http://127.0.0.1:8200/v1/identity/oidc",
#   "namespace": "root",
#   "scopes": "helloworld:read",
#   "sub": "4d616e2c-022e-f914-0c71-60a19539d01c"
# }

resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_policy" "actor_token" {
  for_each = local.client_agents
  name     = each.key

  policy = <<EOT
path "identity/oidc/token/${each.key}" {
  capabilities = ["read"]
}
EOT
}

resource "vault_approle_auth_backend_role" "client_agents" {
  for_each       = local.client_agents
  backend        = vault_auth_backend.approle.path
  role_name      = each.key
  role_id        = each.key
  token_policies = [vault_policy.actor_token[each.key].name]
}

ephemeral "vault_approle_auth_backend_role_secret_id" "client_agents" {
  for_each  = local.client_agents
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.client_agents[each.key].role_name
}

resource "vault_approle_auth_backend_login" "client_agents" {
  for_each             = local.client_agents
  backend              = vault_auth_backend.approle.path
  role_id              = vault_approle_auth_backend_role.client_agents[each.key].role_id
  secret_id_wo         = ephemeral.vault_approle_auth_backend_role_secret_id.client_agents[each.key].secret_id
  secret_id_wo_version = 1
}

resource "vault_identity_entity" "client_agents" {
  for_each = local.client_agents
  name     = each.key
}

resource "vault_identity_entity_alias" "client_agents" {
  for_each       = local.client_agents
  name           = each.key
  mount_accessor = vault_auth_backend.approle.accessor
  canonical_id   = vault_identity_entity.client_agents[each.key].id
}

resource "vault_identity_oidc_role" "client_agents" {
  for_each  = local.client_agents
  name      = each.key
  key       = "default"
  client_id = each.key
  template  = jsonencode(merge(each.value, { client_id = each.key }))
}

# Set up Vault as an OIDC provider
# Scope must include a may_act claim as per RFC 8693.
# Client must get the subject token based on the id_token field
# of the Vault OIDC token endpoint.
# The subject token has the following format.
# {
#   "at_hash": "6KWjQ3hYifa5e5qw1qzIow",
#   "aud": "pZTfZRna11PNtJw3zcWIlPmR0ffAIr4Q",
#   "c_hash": "I5YtF3bXk3LtiUd0y6kGSg",
#   "client_id": "end-user",
#   "exp": 1775241406,
#   "iat": 1775239006,
#   "iss": "http://localhost:8200/v1/identity/oidc/provider/test",
#   "may_act": {
#     "aud": [
#       "second-client",
#       "test-client"
#     ]
#   },
#   "namespace": "root",
#   "sub": "613d7d98-5468-4738-3188-e981026a588d"
# }

resource "vault_identity_oidc_scope" "may_act" {
  name        = "may-act"
  template    = <<EOT
{
  "client_id": "${vault_identity_oidc_client.client.client_id}",
  "may_act": {
    "client_id": "test-client",
    "sub": "${vault_identity_entity.client_agents["test-client"].id}"
  }
}
EOT
  description = "May act claim that includes what agents can act on behalf of user"
}

resource "vault_policy" "agent_oidc_authorize" {
  name = "agent-oidc-authorize"

  policy = <<EOT
path "identity/oidc/provider/${vault_identity_oidc_provider.provider.name}/authorize" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_policy" "agent_oidc_client" {
  name = "agent-oidc-client"

  policy = <<EOT
path "identity/oidc/client/${vault_identity_oidc_provider.provider.name}" {
  capabilities = [ "read" ]
}
EOT
}

resource "vault_policy" "agent_token_verify" {
  name = "agent-token-verify"

  policy = <<EOT
path "identity/oidc/introspect" {
  capabilities = ["update"]
}

path "identity/oidc/introspect/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_auth_backend" "userpass" {
  type = "userpass"
}

resource "random_password" "end_user" {
  length  = 16
  special = false
}

resource "vault_generic_endpoint" "end_user" {
  path                 = "auth/${vault_auth_backend.userpass.path}/users/${local.end_user}"
  ignore_absent_fields = true
  data_json            = <<EOT
{
  "token_policies": ["${vault_policy.agent_oidc_authorize.name}"],
  "token_ttl": "1h",
  "password": "${random_password.end_user.result}"
}
EOT
}

resource "vault_identity_entity" "end_user" {
  name = local.end_user
}

resource "vault_identity_entity_alias" "end_user" {
  name           = local.end_user
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.end_user.id
}

resource "vault_identity_oidc_assignment" "test" {
  name = "test"
  entity_ids = [
    vault_identity_entity.end_user.id,
  ]
}

# Create an OIDC provider for subject tokens
resource "vault_identity_oidc_key" "key" {
  name               = "oauth-token-exchange"
  allowed_client_ids = ["*"]
  rotation_period    = 3600
  verification_ttl   = 3600
}

resource "vault_identity_oidc_client" "client" {
  name = "test"
  key  = vault_identity_oidc_key.key.name
  redirect_uris = [
    "http://localhost:9000/callback",
    "http://localhost:8200/v1/oauth-token-exchange/callback"
  ]
  assignments = [
    vault_identity_oidc_assignment.test.name
  ]
  id_token_ttl     = 2400
  access_token_ttl = 7200
}

resource "vault_identity_oidc_provider" "provider" {
  name          = "test"
  https_enabled = false
  issuer_host   = "localhost:8200"
  allowed_client_ids = [
    vault_identity_oidc_client.client.client_id
  ]
  scopes_supported = [
    vault_identity_oidc_scope.may_act.name
  ]
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

output "client_agent_vault_tokens" {
  value       = { for agent, attributes in vault_approle_auth_backend_login.client_agents : agent => attributes.client_token }
  description = "AppRole secret ids for agents"
  sensitive   = true
}

output "end_user_password" {
  value       = random_password.end_user.result
  description = "End user password"
  sensitive   = true
}