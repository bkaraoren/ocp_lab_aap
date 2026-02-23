#!/bin/bash
# =============================================================================
# AAP Post-Install Configuration Script
# =============================================================================
# Run this AFTER AAP is fully deployed and all pods are running.
#
# This script:
#   1. Creates the Google OAuth2 authenticator in AAP
#   2. Creates the authenticator map for bkaraore@redhat.com (superuser)
#   3. Creates the Self-Service Portal OAuth application
#   4. Enables OAuth for external users
#   5. Generates an admin token for the portal
#
# Prerequisites:
#   - AAP is running (oc get pods -n aap — all Running)
#   - GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are available
#   - oc is logged in to the cluster
#
# Usage:
#   export GOOGLE_CLIENT_ID="775961166307-rio3vds58fl05idalb7c7tbpqjr64vqi.apps.googleusercontent.com"
#   export GOOGLE_CLIENT_SECRET="your-google-client-secret"
#   ./configure-aap.sh
# =============================================================================

set -euo pipefail

GOOGLE_CID="${GOOGLE_CLIENT_ID:?Error: GOOGLE_CLIENT_ID is not set}"
GOOGLE_CSEC="${GOOGLE_CLIENT_SECRET:?Error: GOOGLE_CLIENT_SECRET is not set}"

# Get AAP Gateway details
AAP_GW=$(oc get route aap -n aap -o jsonpath='{.spec.host}')
ADMIN_PASS=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)

echo "============================================"
echo "Configuring AAP Gateway..."
echo "AAP Gateway: https://${AAP_GW}"
echo "============================================"

# 1. Create Google OAuth2 Authenticator
echo ""
echo "→ Creating Google OAuth2 authenticator..."
AUTH_RESULT=$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "https://${AAP_GW}/api/gateway/v1/authenticators/" \
  -d "{
    \"name\": \"Red Hat SSO (Google)\",
    \"enabled\": true,
    \"create_objects\": true,
    \"remove_users\": false,
    \"type\": \"ansible_base.authentication.authenticator_plugins.google_oauth2\",
    \"configuration\": {
      \"SOCIAL_AUTH_GOOGLE_OAUTH2_KEY\": \"${GOOGLE_CID}\",
      \"SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET\": \"${GOOGLE_CSEC}\",
      \"ADDITIONAL_UNVERIFIED_ARGS\": {\"hd\": \"redhat.com\"}
    }
  }")
AUTH_ID=$(echo "$AUTH_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id','ERROR'))" 2>/dev/null || echo "ERROR")
echo "  Authenticator ID: ${AUTH_ID}"

# 2. Create authenticator map (superuser for bkaraore@redhat.com)
if [ "$AUTH_ID" != "ERROR" ]; then
  echo ""
  echo "→ Creating authenticator map (superuser for bkaraore@redhat.com)..."
  curl -sk -X POST \
    -H "Content-Type: application/json" \
    -u "admin:${ADMIN_PASS}" \
    "https://${AAP_GW}/api/gateway/v1/authenticator_maps/" \
    -d "{
      \"name\": \"bkaraore-superuser\",
      \"authenticator\": ${AUTH_ID},
      \"map_type\": \"is_superuser\",
      \"triggers\": {
        \"groups\": {},
        \"attributes\": {
          \"email\": {\"equals\": \"bkaraore@redhat.com\"}
        }
      },
      \"organization\": 1,
      \"revoke\": true
    }" > /dev/null
  echo "  ✅ Authenticator map created"
fi

# 3. Create Self-Service Portal OAuth application
echo ""
echo "→ Creating Self-Service Portal OAuth application..."
PORTAL_URL="https://rhaap-portal-aap-portal.apps.ocp.karaoren.eu"
APP_RESULT=$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "https://${AAP_GW}/api/gateway/v1/applications/" \
  -d "{
    \"name\": \"Self-Service Automation Portal\",
    \"organization\": 1,
    \"client_type\": \"confidential\",
    \"authorization_grant_type\": \"authorization-code\",
    \"redirect_uris\": \"${PORTAL_URL}/api/auth/rhaap/handler/frame\"
  }")

APP_CLIENT_ID=$(echo "$APP_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('client_id','ERROR'))")
APP_CLIENT_SECRET=$(echo "$APP_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('client_secret','ERROR'))")
echo "  Client ID: ${APP_CLIENT_ID}"
echo "  Client Secret: ${APP_CLIENT_SECRET}"

# 4. Enable OAuth for external users
echo ""
echo "→ Enabling OAuth for external users..."
curl -sk -X PUT \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "https://${AAP_GW}/api/gateway/v1/settings/oauth2_provider/" \
  -d '{"ALLOW_OAUTH2_FOR_EXTERNAL_USERS": true}' > /dev/null
echo "  ✅ External users enabled"

# 5. Generate admin token for portal
echo ""
echo "→ Generating admin token for portal..."
TOKEN_RESULT=$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "https://${AAP_GW}/api/gateway/v1/tokens/" \
  -d '{
    "scope": "write",
    "application": 1,
    "description": "Self-Service Portal Token"
  }')
AAP_TOKEN=$(echo "$TOKEN_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token','ERROR'))")
echo "  AAP Token: ${AAP_TOKEN}"

echo ""
echo "============================================"
echo "✅ AAP configuration complete!"
echo "============================================"
echo ""
echo "Portal secrets to store in Vault:"
echo "  vault kv put secret/aap/portal \\"
echo "    aap_host_url='https://${AAP_GW}' \\"
echo "    oauth_client_id='${APP_CLIENT_ID}' \\"
echo "    oauth_client_secret='${APP_CLIENT_SECRET}' \\"
echo "    aap_token='${AAP_TOKEN}'"
echo ""
echo "Google Cloud Console callback URLs to register:"
echo "  - https://${AAP_GW}/complete/google-oauth2/"
