#!/bin/bash

source secrets.env

echo "Registering new plugin to Vault..."

SHA256=$(shasum -a 256 bin/vault-plugin-secrets-oauth-token-exchange | cut -d ' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-secrets-oauth-token-exchange
vault plugin info secret vault-plugin-secrets-oauth-token-exchange

echo "Enabling new plugin secret engine..."

vault secrets enable -path=sts vault-plugin-secrets-oauth-token-exchange
vault write sts/config \
    client_id=$(cd bootstrap/terraform && terraform output -raw oidc_client_id) \
    client_secret=$(cd bootstrap/terraform && terraform output -raw oidc_client_secret) \
    subject_token_jwks_uri=http://localhost:8200/v1/identity/oidc/provider/test/.well-known/keys \
    vault_addr=$VAULT_ADDR \
    vault_token=$VAULT_TOKEN

vault write sts/key/test allowed_client_ids="*"

vault write sts/role/test-client \
    key="test" \
    issuer="http://localhost:8200/v1/identity/oidc/provider/test" \
    actor_token_jwks_uri=http://localhost:8200/v1/identity/oidc/.well-known/keys

vault write sts/role/second-client \
    key="test" \
    issuer="http://localhost:8200/v1/sts/token/test-client" \
    actor_token_jwks_uri=http://localhost:8200/v1/sts/.well-known/keys

echo "Get subject token and actor token manually..."

read -p "Enter subject token: " SUBJECT_TOKEN

ACTOR_TOKEN=$(VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["test-client"]') vault read -format=json identity/oidc/token/test-client | jq -r .data.token)

echo "Create access token..."

TEST_CLIENT_ACCESS_TOKEN=$(VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["test-client"]') vault read -format=json sts/token/test-client \
   subject_token="$SUBJECT_TOKEN" \
   actor_token="$ACTOR_TOKEN" \
   audience="helloworld-server" \
   scope="helloworld:read" | jq -r .data.access_token)

VAULT_TOKEN=$(cd bootstrap/terraform && terraform output -json client_agent_vault_tokens | jq -r '.["second-client"]') vault read sts/token/second-client \
   subject_token="$SUBJECT_TOKEN" \
   actor_token="$TEST_CLIENT_ACCESS_TOKEN" \
   audience="helloworld-server" \
   scope="helloworld:read"