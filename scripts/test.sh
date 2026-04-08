#!/bin/bash

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
    issuer="http://localhost:8200/v1/identity/oidc/provider/test"

export SUBJECT_TOKEN=""
export ACTOR_TOKEN=""

vault write sts/token/test-client \
   subject_token=$SUBJECT_TOKEN \
   actor_token=$ACTOR_TOKEN \
   audience="end-user" \
   scope="helloworld:read"