#!/bin/bash
# Copyright IBM Corp. 2026
# SPDX-License-Identifier: MPL-2.0

vault operator init -key-shares=1 -key-threshold=1 -format=json > secrets/vault-init.json

vault operator unseal

source secrets.env

vault audit enable file file_path=vault/audit.log

echo "Registering new plugin to Vault..."

SHA256=$(shasum -a 256 bin/vault-plugin-secrets-oauth-token-exchange | cut -d ' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-oauth-token-exchange
vault plugin info secret vault-plugin-secrets-oauth-token-exchange

echo "Enabling new plugin secret engine..."

vault secrets enable -path=sts vault-plugin-secrets-oauth-token-exchange

vault secrets tune -audit-non-hmac-request-keys=scope -audit-non-hmac-request-keys=subject -audit-non-hmac-request-keys=audience sts

vault write sts/config \
    client_id=$(cd bootstrap/terraform && terraform output -raw oidc_client_id) \
    client_secret=$(cd bootstrap/terraform && terraform output -raw oidc_client_secret) \
    subject_token_jwks_uri=http://localhost:8200/v1/identity/oidc/provider/test/.well-known/keys

vault write sts/key/test allowed_client_ids="*"

vault write sts/scope/may-act \
    template='{
  "may_act": [{
    "client_id": "test-client",
    "sub": "5257a4df-31a0-8304-987f-8d921a4956a7"
  },{
    "client_id": "second-client",
    "sub": "f2b02b0a-b632-6b0a-d1ce-d1c47c652042"
  }]
}' \
    description="May act claim for delegated access"

vault write sts/role/test-client \
    key="test" \
    issuer="http://localhost:8200/v1/identity/oidc/provider/test" \
    actor_token_jwks_uri=http://localhost:8200/v1/identity/oidc/.well-known/keys \
    scopes_supported=may-act

## STS Delegated endpoint

vault secrets enable -path=sts-delegated vault-plugin-secrets-oauth-token-exchange

vault write sts-delegated/config \
    client_id=$(cd bootstrap/terraform && terraform output -raw oidc_client_id) \
    client_secret=$(cd bootstrap/terraform && terraform output -raw oidc_client_secret) \
    subject_token_jwks_uri=http://localhost:8200/v1/sts/.well-known/keys

vault write sts-delegated/key/test allowed_client_ids="*"

vault write sts-delegated/role/second-client \
    key="test" \
    issuer="http://localhost:8200/v1/sts-delegated" \
    actor_token_jwks_uri=http://localhost:8200/v1/identity/oidc/.well-known/keys \
    scopes_supported=may-act

ACTOR_TOKEN=$(VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["test-client"]') vault read -format=json identity/oidc/token/test-client | jq -r .data.token)

echo "Create access token..."

TEST_CLIENT_ACCESS_TOKEN=$(VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["test-client"]') vault read -format=json sts/token/test-client \
   subject_token="$SUBJECT_TOKEN" \
   actor_token="$ACTOR_TOKEN" \
   audience="helloworld-server" \
   scope="may-act helloworld:read" | jq -r .data.access_token)

SECOND_ACTOR_TOKEN=$(VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["second-client"]') vault read -format=json identity/oidc/token/second-client | jq -r .data.token)

VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["second-client"]') vault read sts-delegated/token/second-client \
   subject_token="$TEST_CLIENT_ACCESS_TOKEN" \
   actor_token="$SECOND_ACTOR_TOKEN" \
   audience="helloworld-server" \
   scope="helloworld:write"