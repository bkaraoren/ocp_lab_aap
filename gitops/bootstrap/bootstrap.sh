#!/bin/bash
# =============================================================================
# OCP SNO Cluster Bootstrap Script
# =============================================================================
# This script bootstraps the entire cluster from scratch using GitOps.
#
# Architecture:
#   Git Repo → ArgoCD → Operators/Apps → Vault → ESO → Secrets → Configs
#
# Deployment order (sync waves):
#   Wave 1:  Namespaces
#   Wave 2:  Operators (CNV, LVMS, AAP, ESO)
#   Wave 3:  Monitoring (Alertmanager/Slack)
#   Wave 4:  Storage (NFS server, CSI driver, StorageClasses)
#   Wave 5:  Vault (Helm)
#   Wave 6:  OAuth (Google SSO, OAuthClients)
#   Wave 7:  Vault ↔ ESO (ClusterSecretStore, NetworkPolicy)
#   Wave 8:  ExternalSecrets (Vault → OCP secret sync)
#   Wave 9:  AAP instance
#   Wave 10: TLS certificates (IngressController, APIServer)
#   Wave 11: Self-Service Portal (Helm)
#
# Manual steps required (cannot be automated via GitOps):
#   - Vault init + unseal
#   - Vault configuration (policies, auth, OIDC)
#   - Vault secret population
#   - AAP post-install configuration (OAuth app, authenticator)
#   - Alertmanager secret (from Vault)
#   - Let's Encrypt certificate generation (acme.sh)
#   - Google Cloud Console callback URL registration
#   - NFS server SCC grant
#
# Usage:
#   export GIT_REPO_URL="https://github.com/YOUR_ORG/aap-ocp-karaoren.git"
#   ./bootstrap.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITOPS_DIR="$(dirname "$SCRIPT_DIR")"

GIT_REPO="${GIT_REPO_URL:?Error: GIT_REPO_URL is not set (e.g. https://github.com/YOUR_ORG/aap-ocp-karaoren.git)}"

echo "============================================================"
echo "  OCP SNO Cluster Bootstrap"
echo "  Git Repo: ${GIT_REPO}"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────
# Phase 0: Verify prerequisites
# ─────────────────────────────────────────────
echo "Phase 0: Checking prerequisites..."
command -v oc >/dev/null 2>&1 || { echo "❌ oc CLI not found"; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "❌ helm CLI not found"; exit 1; }
oc whoami >/dev/null 2>&1 || { echo "❌ Not logged in to OCP"; exit 1; }
echo "  ✅ oc CLI: $(oc version --client -o json | python3 -c 'import sys,json; print(json.load(sys.stdin)["releaseClientVersion"])')"
echo "  ✅ helm CLI: $(helm version --short)"
echo "  ✅ Logged in as: $(oc whoami)"
echo "  ✅ Cluster: $(oc whoami --show-server)"
echo ""

# ─────────────────────────────────────────────
# Phase 1: Install OpenShift GitOps operator
# ─────────────────────────────────────────────
echo "Phase 1: Installing OpenShift GitOps operator..."
oc apply -f "${GITOPS_DIR}/argocd/gitops-subscription.yaml"

echo "  Waiting for GitOps operator to be ready..."
for i in $(seq 1 60); do
  if oc get csv -n openshift-gitops-operator 2>/dev/null | grep -q Succeeded; then
    echo "  ✅ GitOps operator installed"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "  ⚠️  Timeout waiting for GitOps operator (will continue)"
  fi
  sleep 10
done

echo "  Waiting for ArgoCD pods to be ready..."
for i in $(seq 1 60); do
  READY=$(oc get pods -n openshift-gitops --no-headers 2>/dev/null | grep -c Running || true)
  if [ "$READY" -ge 5 ]; then
    echo "  ✅ ArgoCD pods running ($READY pods)"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "  ⚠️  Timeout waiting for ArgoCD pods (will continue)"
  fi
  sleep 10
done

# ─────────────────────────────────────────────
# Phase 2: Grant ArgoCD cluster-admin
# ─────────────────────────────────────────────
echo ""
echo "Phase 2: Granting ArgoCD cluster-admin..."
oc apply -f "${GITOPS_DIR}/argocd/cluster-role.yaml"
echo "  ✅ ClusterRoleBinding created"

# ─────────────────────────────────────────────
# Phase 3: Create AppProject
# ─────────────────────────────────────────────
echo ""
echo "Phase 3: Creating ArgoCD AppProject..."

# Update repo URL in AppProject
sed "s|https://github.com/YOUR_ORG/aap-ocp-karaoren.git|${GIT_REPO}|g" \
  "${GITOPS_DIR}/argocd/appproject.yaml" | oc apply -f -
echo "  ✅ AppProject 'sno-cluster' created"

# ─────────────────────────────────────────────
# Phase 4: Deploy all ArgoCD Applications
# ─────────────────────────────────────────────
echo ""
echo "Phase 4: Deploying ArgoCD Applications..."

# Update repo URL in all application manifests and apply
for app_file in "${GITOPS_DIR}/argocd/applications/"*.yaml; do
  if [ "$(basename "$app_file")" = "kustomization.yaml" ]; then
    continue
  fi
  echo "  → Applying $(basename "$app_file")..."
  sed "s|https://github.com/YOUR_ORG/aap-ocp-karaoren.git|${GIT_REPO}|g" \
    "$app_file" | oc apply -f -
done
echo "  ✅ All Applications created"

# ─────────────────────────────────────────────
# Phase 5: Pre-requisite manual steps
# ─────────────────────────────────────────────
echo ""
echo "Phase 5: NFS server SCC..."
echo "  Waiting for nfs-server namespace..."
for i in $(seq 1 30); do
  if oc get namespace nfs-server >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
oc adm policy add-scc-to-user privileged -z nfs-server -n nfs-server 2>/dev/null || true
echo "  ✅ NFS server SCC granted"

echo ""
echo "============================================================"
echo "  ✅ Bootstrap Phase Complete!"
echo "============================================================"
echo ""
echo "ArgoCD will now sync all applications in wave order."
echo "Monitor progress at: https://$(oc get route openshift-gitops-server -n openshift-gitops -o jsonpath='{.spec.host}')"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  MANUAL STEPS REQUIRED (in order):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. VAULT INITIALIZATION"
echo "   Wait for Vault pod to be running, then:"
echo "   oc exec -n vault vault-0 -- vault operator init -key-shares=1 -key-threshold=1"
echo "   oc exec -n vault vault-0 -- vault operator unseal <UNSEAL_KEY>"
echo ""
echo "2. VAULT CONFIGURATION"
echo "   export VAULT_ROOT_TOKEN=<root-token>"
echo "   export GOOGLE_CLIENT_ID=<your-google-client-id>"
echo "   export GOOGLE_CLIENT_SECRET=<your-google-client-secret>"
echo "   ${GITOPS_DIR}/apps/vault/configure-vault.sh"
echo ""
echo "3. LETS ENCRYPT CERTIFICATES"
echo "   export NAMECOM_USERNAME=<your-user>"
echo "   export NAMECOM_API_TOKEN=<your-token>"
echo "   ${SCRIPT_DIR}/generate-certs.sh"
echo ""
echo "4. STORE ALL SECRETS IN VAULT"
echo "   export VAULT_ROOT_TOKEN=<root-token>"
echo "   export SLACK_WEBHOOK_URL=<your-slack-webhook>"
echo "   export NAMECOM_USERNAME=<your-user>"
echo "   export NAMECOM_API_TOKEN=<your-token>"
echo "   ${GITOPS_DIR}/apps/vault/store-secrets-in-vault.sh"
echo ""
echo "5. ALERTMANAGER CONFIG"
echo "   Get Slack URL from Vault and apply:"
echo "   SLACK_URL=\$(oc exec -n vault vault-0 -- sh -c \"VAULT_TOKEN='<token>' vault kv get -field=webhook_url secret/ocp/slack\")"
echo "   sed \"s|REPLACE_WITH_VAULT_SECRET_ocp_slack_webhook_url|\$SLACK_URL|\" ${GITOPS_DIR}/cluster/monitoring/alertmanager.yaml > /tmp/alertmanager.yaml"
echo "   oc -n openshift-monitoring create secret generic alertmanager-main --from-file=alertmanager.yaml=/tmp/alertmanager.yaml --dry-run=client -o yaml | oc apply -f -"
echo ""
echo "6. AAP CONFIGURATION (after AAP pods are all Running)"
echo "   export GOOGLE_CLIENT_ID=<your-google-client-id>"
echo "   export GOOGLE_CLIENT_SECRET=<your-google-client-secret>"
echo "   ${GITOPS_DIR}/apps/aap-instance/configure-aap.sh"
echo "   → Then store the portal secrets in Vault (script will print the command)"
echo ""
echo "7. GOOGLE CLOUD CONSOLE"
echo "   Register these callback URLs as authorized redirect URIs:"
echo "   - https://oauth-openshift.apps.ocp.karaoren.eu/oauth2callback/RedHatSSO"
echo "   - https://aap-aap.apps.ocp.karaoren.eu/complete/google-oauth2/"
echo "   - https://vault.apps.ocp.karaoren.eu/ui/vault/auth/oidc/oidc/callback"
echo ""
echo "8. OAUTH SECRETS"
echo "   Create OAuth secrets in openshift-config namespace:"
echo "   oc create secret generic github-client-secret --from-literal=clientSecret=<github-secret> -n openshift-config"
echo "   oc create secret generic google-client-secret --from-literal=clientSecret=<google-secret> -n openshift-config"
echo ""
