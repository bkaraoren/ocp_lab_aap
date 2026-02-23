#!/bin/bash
# =============================================================================
# Store All Cluster Secrets in Vault
# =============================================================================
# Populates Vault with all secrets needed by the cluster.
# Run this AFTER Vault is initialized, unsealed, and configured.
#
# Prerequisites:
#   - Vault is running and unsealed
#   - KV v2 engine is enabled at secret/
#   - VAULT_ROOT_TOKEN is set
#   - oc is logged in to the cluster
#   - acme.sh certificates exist (for Let's Encrypt secrets)
#
# Usage:
#   export VAULT_ROOT_TOKEN="hvs.xxxxx"
#   export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
#   export GOOGLE_CLIENT_SECRET="your-google-client-secret"
#   export NAMECOM_USERNAME="your-namecom-user"
#   export NAMECOM_API_TOKEN="your-namecom-token"
#   ./store-secrets-in-vault.sh
# =============================================================================

set -euo pipefail

VT="${VAULT_ROOT_TOKEN:?Error: VAULT_ROOT_TOKEN is not set}"
VAULT_CMD="oc exec -n vault vault-0 -- sh -c"

echo "============================================"
echo "Storing all secrets in Vault..."
echo "============================================"

# 1. Google OAuth
echo "→ Storing Google OAuth credentials..."
GOOGLE_ID=$(oc get oauth cluster -o jsonpath='{.spec.identityProviders[?(@.name=="RedHatSSO")].google.clientID}')
GOOGLE_SECRET_NAME=$(oc get oauth cluster -o jsonpath='{.spec.identityProviders[?(@.name=="RedHatSSO")].google.clientSecret.name}')
GOOGLE_SECRET=$(oc get secret "$GOOGLE_SECRET_NAME" -n openshift-config -o jsonpath='{.data.clientSecret}' | base64 -d)
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/ocp/google-oauth client_id='$GOOGLE_ID' client_secret='$GOOGLE_SECRET'"
echo "  ✅ secret/ocp/google-oauth"

# 2. Slack
echo "→ Storing Slack webhook..."
SLACK_URL="${SLACK_WEBHOOK_URL:?Error: SLACK_WEBHOOK_URL is not set}"
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/ocp/slack webhook_url='$SLACK_URL' channel='#alerts-ocp-karaoren'"
echo "  ✅ secret/ocp/slack"

# 3. AAP Gateway OAuthClient
echo "→ Storing AAP Gateway OAuthClient..."
AAP_OAUTH=$(oc get oauthclient aap-gateway -o jsonpath='{.secret}')
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/ocp/aap-gateway-oauth client_name='aap-gateway' client_secret='$AAP_OAUTH'"
echo "  ✅ secret/ocp/aap-gateway-oauth"

# 4. AAP Admin
echo "→ Storing AAP admin credentials..."
AAP_PW=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/aap/admin username='admin' password='$AAP_PW'"
echo "  ✅ secret/aap/admin"

# 5. Portal secrets
echo "→ Storing portal secrets..."
P_HOST=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.aap-host-url}' | base64 -d 2>/dev/null || echo "https://aap-aap.apps.ocp.karaoren.eu")
P_OID=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.oauth-client-id}' | base64 -d 2>/dev/null || echo "REPLACE_ME")
P_OSEC=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.oauth-client-secret}' | base64 -d 2>/dev/null || echo "REPLACE_ME")
P_TOK=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.aap-token}' | base64 -d 2>/dev/null || echo "REPLACE_ME")
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/aap/portal aap_host_url='$P_HOST' oauth_client_id='$P_OID' oauth_client_secret='$P_OSEC' aap_token='$P_TOK'"
echo "  ✅ secret/aap/portal"

# 6. SCM tokens (placeholder)
echo "→ Storing SCM tokens..."
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/aap/scm github_token='placeholder' gitlab_token='placeholder'"
echo "  ✅ secret/aap/scm"

# 7. Vault tokens
echo "→ Storing Vault tokens..."
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/vault/tokens root_token='$VT' unseal_key='REPLACE_WITH_UNSEAL_KEY'"
echo "  ✅ secret/vault/tokens"

# 8. Let's Encrypt certificates (if acme.sh certs exist)
CERT_DIR="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc"
if [ -d "$CERT_DIR" ]; then
  echo "→ Storing Let's Encrypt certificates..."
  KEY_B64=$(cat "$CERT_DIR"/*.apps.ocp.karaoren.eu.key | base64)
  CHAIN_B64=$(cat "$CERT_DIR"/fullchain.cer | base64)
  CA_B64=$(cat "$CERT_DIR"/ca.cer | base64)
  $VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/letsencrypt/certs \
    domain='*.apps.ocp.karaoren.eu' alt_domain='api.ocp.karaoren.eu' \
    private_key_b64='$KEY_B64' fullchain_b64='$CHAIN_B64' ca_b64='$CA_B64'"
  echo "  ✅ secret/letsencrypt/certs"
else
  echo "  ⚠️  Skipping Let's Encrypt certs (acme.sh directory not found)"
  echo "     Run acme.sh first, then re-run this script"
fi

# 9. Registry pull secret
echo "→ Storing registry pull secret..."
PS_B64=$(oc get secret pull-secret -n openshift-config -o jsonpath='{.data.\.dockerconfigjson}')
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/registry/pull-secret registry='registry.redhat.io' dockerconfigjson_b64='$PS_B64'"
echo "  ✅ secret/registry/pull-secret"

# 10. DNS provider
echo "→ Storing name.com DNS credentials..."
NC_USER="${NAMECOM_USERNAME:?Error: NAMECOM_USERNAME is not set}"
NC_TOKEN="${NAMECOM_API_TOKEN:?Error: NAMECOM_API_TOKEN is not set}"
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/dns/namecom username='$NC_USER' api_token='$NC_TOKEN'"
echo "  ✅ secret/dns/namecom"

echo ""
echo "============================================"
echo "✅ All secrets stored in Vault!"
echo "============================================"
