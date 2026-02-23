#!/bin/bash
# =============================================================================
# Let's Encrypt Certificate Generation Script
# =============================================================================
# Generates wildcard TLS certificates using acme.sh with name.com DNS-01 challenge.
#
# Prerequisites:
#   - acme.sh installed (curl https://get.acme.sh | sh -s email=bkaraore@redhat.com)
#   - name.com API credentials
#
# Usage:
#   export NAMECOM_USERNAME="your-namecom-user"
#   export NAMECOM_API_TOKEN="your-namecom-token"
#   ./generate-certs.sh
# =============================================================================

set -euo pipefail

export Namecom_Username="${NAMECOM_USERNAME:?Error: NAMECOM_USERNAME is not set}"
export Namecom_Token="${NAMECOM_API_TOKEN:?Error: NAMECOM_API_TOKEN is not set}"

ACME_SH="$HOME/.acme.sh/acme.sh"

# Install acme.sh if not present
if [ ! -f "$ACME_SH" ]; then
  echo "→ Installing acme.sh..."
  curl https://get.acme.sh | sh -s email=bkaraore@redhat.com
fi

echo "============================================"
echo "Generating Let's Encrypt certificates..."
echo "============================================"

# Issue wildcard + API certificate
$ACME_SH --issue \
  -d "*.apps.ocp.karaoren.eu" \
  -d "api.ocp.karaoren.eu" \
  --dns dns_namecom \
  --server letsencrypt

CERT_DIR="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc"

echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_DIR"/*.apps.ocp.karaoren.eu.cer -text -noout | \
  grep -E 'Subject:|Issuer:|Not Before:|Not After:|DNS:'

echo ""
echo "Files location: $CERT_DIR"
echo ""
echo "✅ Certificates generated successfully!"
echo ""
echo "Next: Run store-secrets-in-vault.sh to store the certs in Vault"
