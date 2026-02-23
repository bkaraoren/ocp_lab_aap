#!/bin/bash
# =============================================================================
# Vault Post-Install Configuration Script
# =============================================================================
# Run this AFTER Vault is deployed and unsealed.
# Prerequisites:
#   - Vault pod is running and unsealed
#   - VAULT_ROOT_TOKEN is set
#   - GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are available
#
# Usage:
#   export VAULT_ROOT_TOKEN="hvs.xxxxx"
#   export GOOGLE_CLIENT_ID="775961166307-rio3vds58fl05idalb7c7tbpqjr64vqi.apps.googleusercontent.com"
#   export GOOGLE_CLIENT_SECRET="your-google-client-secret"
#   ./configure-vault.sh
# =============================================================================

set -euo pipefail

VAULT_NS="vault"
VT="${VAULT_ROOT_TOKEN:?Error: VAULT_ROOT_TOKEN is not set}"
GOOGLE_CID="${GOOGLE_CLIENT_ID:?Error: GOOGLE_CLIENT_ID is not set}"
GOOGLE_CSEC="${GOOGLE_CLIENT_SECRET:?Error: GOOGLE_CLIENT_SECRET is not set}"

VAULT_EXEC="oc exec -n ${VAULT_NS} vault-0 -- sh -c"

echo "============================================"
echo "Configuring Vault..."
echo "============================================"

# 1. Enable KV v2 secrets engine
echo "→ Enabling KV v2 secrets engine at secret/..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault secrets enable -path=secret kv-v2" 2>/dev/null || echo "  (already enabled)"

# 2. Enable Kubernetes auth method
echo "→ Enabling Kubernetes auth method..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault auth enable kubernetes" 2>/dev/null || echo "  (already enabled)"

# 3. Configure Kubernetes auth
echo "→ Configuring Kubernetes auth (in-cluster)..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault write auth/kubernetes/config \
  kubernetes_host=\"https://\$KUBERNETES_SERVICE_HOST:\$KUBERNETES_SERVICE_PORT\" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# 4. Create policies
echo "→ Creating admin policy..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault policy write admin -" <<'EOF'
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF

echo "→ Creating aap-policy..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault policy write aap-policy -" <<'EOF'
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

echo "→ Creating external-secrets policy..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault policy write external-secrets -" <<'EOF'
path "secret/data/*" {
  capabilities = ["read"]
}
EOF

# 5. Create Kubernetes auth roles
echo "→ Creating AAP Kubernetes auth role..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault write auth/kubernetes/role/aap \
  bound_service_account_names='*' \
  bound_service_account_namespaces=aap \
  policies=aap-policy \
  ttl=24h"

echo "→ Creating External Secrets Kubernetes auth role..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault write auth/kubernetes/role/external-secrets \
  bound_service_account_names=external-secrets \
  bound_service_account_namespaces=external-secrets \
  policies=external-secrets \
  ttl=24h"

# 6. Enable OIDC auth method (Google)
echo "→ Enabling OIDC auth method..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault auth enable oidc" 2>/dev/null || echo "  (already enabled)"

echo "→ Configuring OIDC with Google..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault write auth/oidc/config \
  oidc_discovery_url='https://accounts.google.com' \
  oidc_client_id='$GOOGLE_CID' \
  oidc_client_secret='$GOOGLE_CSEC' \
  default_role='redhat-user'"

echo "→ Creating OIDC role (admin for bkaraore@redhat.com only)..."
$VAULT_EXEC "VAULT_TOKEN='$VT' vault write auth/oidc/role/redhat-user \
  bound_audiences='$GOOGLE_CID' \
  allowed_redirect_uris='https://vault.apps.ocp.karaoren.eu/ui/vault/auth/oidc/oidc/callback' \
  allowed_redirect_uris='http://localhost:8250/oidc/callback' \
  user_claim='email' \
  policies='admin' \
  oidc_scopes='openid,email,profile' \
  bound_claims='{\"hd\":\"redhat.com\",\"email\":\"bkaraore@redhat.com\"}'"

# 7. Create AAP integration token
echo "→ Creating long-lived AAP integration token..."
AAP_TOKEN=$($VAULT_EXEC "VAULT_TOKEN='$VT' vault token create \
  -policy=aap-policy \
  -period=8760h \
  -display-name='AAP Integration Token' \
  -format=json" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")
echo "  AAP Integration Token: ${AAP_TOKEN}"

echo ""
echo "============================================"
echo "✅ Vault configuration complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Save the AAP Integration Token above"
echo "  2. Register these callback URLs in Google Cloud Console:"
echo "     - https://vault.apps.ocp.karaoren.eu/ui/vault/auth/oidc/oidc/callback"
echo "  3. Run store-secrets-in-vault.sh to populate Vault with all cluster secrets"
