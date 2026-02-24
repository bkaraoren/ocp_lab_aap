# OCP SNO Cluster Configuration Documentation

**Cluster:** ocp.karaoren.eu (Single-Node OpenShift)  
**Version:** 4.20.14 (upgraded from 4.19.24)  
**Date:** February 18, 2026

---

## Table of Contents

1. [Cluster Upgrade](#1-cluster-upgrade-41924--42014)
2. [Alertmanager & Slack Integration](#2-alertmanager--slack-integration)
3. [NFS Storage (RWX)](#3-nfs-storage-rwx-for-sno)
4. [Ansible Automation Platform 2.6](#4-ansible-automation-platform-26)
5. [HashiCorp Vault CE](#5-hashicorp-vault-ce)
6. [OpenShift OAuth (Google/Red Hat SSO)](#6-openshift-oauth-googlered-hat-sso)
7. [AAP Authentication (Google OAuth2)](#7-aap-authentication-google-oauth2)
8. [Vault OIDC Authentication](#8-vault-oidc-authentication-google)
9. [External Secrets Operator](#9-external-secrets-operator)
10. [Self-Service Automation Portal](#10-self-service-automation-portal)
11. [Let's Encrypt TLS Certificates](#11-lets-encrypt-tls-certificates)
12. [Secrets Stored in Vault](#12-secrets-stored-in-vault)
13. [GitOps Deployment](#13-gitops-deployment)
14. [Ansible Playbooks (Alternative to Shell Scripts)](#14-ansible-playbooks-alternative-to-shell-scripts)
15. [Automated Certificate Renewal (AAP Scheduled Job)](#15-automated-certificate-renewal-aap-scheduled-job)
16. [AAP Execution Node (RHEL 9 VM)](#16-aap-execution-node-rhel-9-vm)
17. [Node System Tuning (Kubelet Reserved Resources)](#17-node-system-tuning-kubelet-reserved-resources)

---

## 1. Cluster Upgrade (4.19.24 → 4.20.14)

### Upgrade Commands

```bash
# Set the upgrade channel
oc adm upgrade channel stable-4.20

# Force upgrade to 4.20.14 (no validated graph path from 4.19.24)
oc adm upgrade --to-image=quay.io/openshift-release-dev/ocp-release@sha256:<4.20.14-digest> \
  --allow-explicit-upgrade --force

# Monitor upgrade progress
oc adm upgrade
oc get clusterversion
oc get co
oc get nodes
```

### Post-Upgrade: Fix Operator Subscriptions

```bash
# Fix CNV subscription channel (was incorrectly set to stable-4.20)
oc patch subscription kubevirt-hyperconverged -n openshift-cnv \
  --type='json' -p='[{"op": "replace", "path": "/spec/channel", "value": "stable"}]'

# Update LVMS subscription to 4.20
oc patch subscription lvms-operator -n openshift-storage \
  --type='json' -p='[{"op": "replace", "path": "/spec/channel", "value": "stable-4.20"}]'

# Clean up stale install plans
oc delete installplan -n openshift-cnv --all
oc delete installplan -n openshift-storage --all

# Clean up old CSVs
oc delete csv lvms-operator.v4.18.4 -n openshift-storage
```

---

## 2. Alertmanager & Slack Integration

### Cluster Monitoring ConfigMap

```yaml
# File: cluster-monitoring-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
```

```bash
oc apply -f cluster-monitoring-config.yaml
```

### Alertmanager Configuration

```yaml
# Applied via: oc apply -f alertmanager-config-secret.yaml
# Or via: oc -n openshift-monitoring create secret generic alertmanager-main \
#   --from-file=alertmanager.yaml --dry-run=client -o yaml | oc apply -f -
#
# File: alertmanager.yaml
global:
  http_config:
    proxy_from_environment: true
  slack_api_url: "<slack-webhook-url>"
inhibit_rules:
- equal:
  - namespace
  - alertname
  source_matchers:
  - "severity = critical"
  target_matchers:
  - "severity =~ warning|info"
- equal:
  - namespace
  - alertname
  source_matchers:
  - "severity = warning"
  target_matchers:
  - "severity = info"
receivers:
- name: Default
  slack_configs:
  - channel: "#alerts-ocp-karaoren"
    send_resolved: true
    icon_url: https://avatars3.githubusercontent.com/u/3380462
    title: |-
      [{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .CommonLabels.alertname }}
    text: >-
      {{ range .Alerts -}}
      *Alert:* {{ .Labels.alertname }} - {{ .Labels.severity | toUpper }}

      *Description:* {{ .Annotations.description }}

      *Details:*
        {{ range .Labels.SortedPairs }} • *{{ .Name }}:* `{{ .Value }}`
        {{ end }}
      {{ end }}
- name: Watchdog
  slack_configs:
  - channel: "#alerts-ocp-karaoren"
    send_resolved: true
    title: "Watchdog - Cluster Heartbeat"
    text: "Cluster monitoring is active and healthy."
- name: Critical
  slack_configs:
  - channel: "#alerts-ocp-karaoren"
    send_resolved: true
    icon_url: https://avatars3.githubusercontent.com/u/3380462
    title: |-
      🔴 CRITICAL [{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .CommonLabels.alertname }}
    text: >-
      {{ range .Alerts -}}
      *Alert:* {{ .Labels.alertname }} - CRITICAL

      *Description:* {{ .Annotations.description }}

      *Summary:* {{ .Annotations.summary }}

      *Details:*
        {{ range .Labels.SortedPairs }} • *{{ .Name }}:* `{{ .Value }}`
        {{ end }}
      {{ end }}
route:
  group_by:
  - namespace
  group_interval: 5m
  group_wait: 30s
  receiver: Default
  repeat_interval: 12h
  routes:
  - matchers:
    - "alertname = Watchdog"
    receiver: Watchdog
    repeat_interval: 24h
  - matchers:
    - "severity = critical"
    receiver: Critical
```

### Apply Alertmanager Config

```bash
oc -n openshift-monitoring create secret generic alertmanager-main \
  --from-file=alertmanager.yaml=alertmanager.yaml \
  --dry-run=client -o yaml | oc apply -f -
```

---

## 3. NFS Storage (RWX) for SNO

### 3.1 NFS Server Deployment

```yaml
# File: nfs-server-deployment.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: nfs-server
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nfs-server
  namespace: nfs-server
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: nfs-backing-storage
  namespace: nfs-server
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  storageClassName: lvms-vm-vg1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nfs-server
  namespace: nfs-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nfs-server
  template:
    metadata:
      labels:
        app: nfs-server
    spec:
      serviceAccountName: nfs-server
      containers:
        - name: nfs-server
          image: registry.k8s.io/volume-nfs:0.8
          securityContext:
            privileged: true
          ports:
            - name: nfs
              containerPort: 2049
            - name: mountd
              containerPort: 20048
            - name: rpcbind
              containerPort: 111
          volumeMounts:
            - name: nfs-volume
              mountPath: /exports
      volumes:
        - name: nfs-volume
          persistentVolumeClaim:
            claimName: nfs-backing-storage
---
apiVersion: v1
kind: Service
metadata:
  name: nfs-server
  namespace: nfs-server
spec:
  selector:
    app: nfs-server
  ports:
    - name: nfs
      port: 2049
    - name: mountd
      port: 20048
    - name: rpcbind
      port: 111
```

### NFS Server SCC

```bash
# Grant privileged SCC to the NFS server service account
oc adm policy add-scc-to-user privileged -z nfs-server -n nfs-server
```

### 3.2 NFS CSI Driver

```bash
# Install NFS CSI driver via official Helm chart
helm repo add csi-driver-nfs https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/charts

helm install csi-driver-nfs csi-driver-nfs/csi-driver-nfs \
  --namespace kube-system \
  --set controller.replicas=1 \
  --set controller.runOnControlPlane=true \
  --version v4.9.0
```

> **Note:** An earlier manual deployment of the NFS CSI driver had a broken liveness probe configuration causing `CrashLoopBackOff`. It was replaced with the official Helm chart (`v4.9.0`) which resolved the issue.

### 3.3 NFS StorageClass

```yaml
# File: nfs-csi-storageclass.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-csi
  annotations:
    storageclass.kubernetes.io/is-default-class: "false"
    storageclass.kubevirt.io/is-default-virt-class: "true"
provisioner: nfs.csi.k8s.io
parameters:
  server: nfs-server.nfs-server.svc.cluster.local
  share: /
  subDir: ${pvc.metadata.namespace}-${pvc.metadata.name}
mountOptions:
  - nfsvers=4.1
  - hard
reclaimPolicy: Delete
volumeBindingMode: Immediate
```

### 3.4 NFS VolumeSnapshotClass

```yaml
# File: nfs-csi-volumesnapshotclass.yaml
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: nfs-csi
driver: nfs.csi.k8s.io
deletionPolicy: Delete
```

```bash
oc apply -f nfs-csi-storageclass.yaml
oc apply -f nfs-csi-volumesnapshotclass.yaml
```

---

## 4. Ansible Automation Platform 2.6

### 4.1 Operator Installation

```yaml
# File: aap.yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: aap
  labels:
    openshift.io/cluster-monitoring: "true"
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: aap-operator-group
  namespace: aap
spec:
  targetNamespaces:
    - aap
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: ansible-automation-platform-operator
  namespace: aap
spec:
  channel: stable-2.6
  installPlanApproval: Automatic
  name: ansible-automation-platform-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
```

### 4.2 AAP Custom Resource

```yaml
# File: aap-cr.yaml
apiVersion: aap.ansible.com/v1alpha1
kind: AnsibleAutomationPlatform
metadata:
  name: aap
  namespace: aap
spec:
  controller:
    disabled: false
  eda:
    disabled: false
  hub:
    disabled: false
    file_storage_storage_class: nfs-csi
    file_storage_access_mode: ReadWriteMany
    file_storage_size: 10Gi
```

```bash
oc apply -f aap.yaml
# Wait for operator pods to be running
oc get pods -n aap -w
# Deploy AAP instance
oc apply -f aap-cr.yaml
```

### 4.3 AAP Access

| Component | URL |
|---|---|
| AAP Gateway | https://aap-aap.apps.ocp.karaoren.eu |
| Controller | https://aap-controller-aap.apps.ocp.karaoren.eu |
| EDA | https://aap-eda-aap.apps.ocp.karaoren.eu |
| Hub | https://aap-hub-aap.apps.ocp.karaoren.eu |

```bash
# Get admin password
oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d
```

---

## 5. HashiCorp Vault CE

### 5.1 Helm Installation

```bash
# Add Helm repo
helm repo add hashicorp https://helm.releases.hashicorp.com

# Create namespace
oc new-project vault

# Create values file for SNO (disable anti-affinity)
```

```yaml
# File: vault-values.yaml
server:
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution: []
  replicas: 1
injector:
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution: []
  replicas: 1
```

```bash
# Install Vault
helm install vault hashicorp/vault \
  --namespace vault \
  -f vault-values.yaml

# Initialize Vault (single key share for simplicity)
oc exec -n vault vault-0 -- vault operator init -key-shares=1 -key-threshold=1

# Unseal Vault
oc exec -n vault vault-0 -- vault operator unseal <UNSEAL_KEY>
```

### 5.2 Vault Route

```bash
oc create route edge vault --service=vault --port=8200 -n vault
```

### 5.3 Vault Configuration Script

```bash
# Login with root token
export VAULT_TOKEN="<vault-root-token>"

# Enable KV v2 secrets engine
oc exec -n vault vault-0 -- vault secrets enable -path=secret kv-v2

# Enable Kubernetes auth method
oc exec -n vault vault-0 -- vault auth enable kubernetes

# Configure Kubernetes auth (using in-cluster service account)
oc exec -n vault vault-0 -- sh -c 'vault write auth/kubernetes/config \
  kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'

# Create AAP policy
oc exec -n vault vault-0 -- vault policy write aap-policy - <<EOF
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Create AAP Kubernetes auth role
oc exec -n vault vault-0 -- vault write auth/kubernetes/role/aap \
  bound_service_account_names="*" \
  bound_service_account_namespaces=aap \
  policies=aap-policy \
  ttl=24h

# Create long-lived token for AAP
oc exec -n vault vault-0 -- vault token create \
  -policy=aap-policy \
  -period=8760h \
  -display-name="AAP Integration Token"

# Create test secret
oc exec -n vault vault-0 -- vault kv put secret/test \
  username=testuser \
  password=<test-password>
```

### 5.4 Vault Admin Restriction (bkaraore@redhat.com only)

```bash
# Create admin policy
oc exec -n vault vault-0 -- vault policy write admin - <<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF

# OIDC role restricts admin access to specific email
# (configured in Section 8)
```

### 5.5 Vault Unseal After Restart

```bash
# If Vault pod restarts, unseal with:
oc exec -n vault vault-0 -- vault operator unseal "<vault-unseal-key>"
```

---

## 6. OpenShift OAuth (Google/Red Hat SSO)

### OAuth Configuration (existing)

```yaml
# Current OAuth spec (oc get oauth cluster -o yaml)
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:
  - name: github
    type: GitHub
    mappingMethod: claim
    github:
      clientID: <github-client-id>
      clientSecret:
        name: <github-client-secret-name>
      teams:
      - redhat-cop/rhis-code-admins
  - name: RedHatSSO
    type: Google
    mappingMethod: claim
    google:
      clientID: <google-oauth-client-id>.apps.googleusercontent.com
      clientSecret:
        name: <google-client-secret-name>
      hostedDomain: redhat.com
```

---

## 7. AAP Authentication (Google OAuth2)

### 7.1 OAuthClient for AAP Gateway

```yaml
# File: aap-oauthclient.yaml
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: aap-gateway
grantMethod: auto
secret: "<aap-oauthclient-secret>"
redirectURIs:
  - https://aap-aap.apps.ocp.karaoren.eu/api/gateway/v1/sso/complete/openshift/
  - https://aap-aap.apps.ocp.karaoren.eu/api/gateway/v1/sso/complete/oidc/
  - https://aap-aap.apps.ocp.karaoren.eu/sso/complete/openshift/
  - https://aap-aap.apps.ocp.karaoren.eu/sso/complete/oidc/
```

```bash
oc apply -f aap-oauthclient.yaml
```

### 7.2 AAP Gateway Authenticator (Google OAuth2)

Configured via AAP Gateway API:

```bash
AAP_GW_POD=$(oc get pods -n aap -l app.kubernetes.io/name=aap-gateway -o jsonpath='{.items[0].metadata.name}')
ADMIN_PASS=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)

# Create Google OAuth2 Authenticator
oc exec -n aap ${AAP_GW_POD} -- curl -sk \
  -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "http://localhost:8080/api/gateway/v1/authenticators/" \
  -d '{
    "name": "Red Hat SSO (Google)",
    "enabled": true,
    "create_objects": true,
    "remove_users": false,
    "type": "ansible_base.authentication.authenticator_plugins.google_oauth2",
    "configuration": {
      "SOCIAL_AUTH_GOOGLE_OAUTH2_KEY": "<google-oauth-client-id>.apps.googleusercontent.com",
      "SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET": "<google-client-secret>",
      "ADDITIONAL_UNVERIFIED_ARGS": {"hd": "redhat.com"}
    }
  }'
```

### 7.3 AAP Authenticator Map (Admin Access for bkaraore@redhat.com)

```bash
# Create authenticator map to grant superuser access
oc exec -n aap ${AAP_GW_POD} -- curl -sk \
  -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "http://localhost:8080/api/gateway/v1/authenticator_maps/" \
  -d '{
    "name": "bkaraore-superuser",
    "authenticator": <authenticator_id>,
    "map_type": "is_superuser",
    "triggers": {
      "always": {}
    },
    "organization": 1,
    "revoke": true
  }'

# Update trigger to match only bkaraore@redhat.com
oc exec -n aap ${AAP_GW_POD} -- curl -sk \
  -X PATCH \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "http://localhost:8080/api/gateway/v1/authenticator_maps/<map_id>/" \
  -d '{
    "triggers": {
      "groups": {},
      "attributes": {
        "email": {"equals": "bkaraore@redhat.com"}
      }
    }
  }'
```

> **Google Cloud Console:** The AAP callback URL `https://aap-aap.apps.ocp.karaoren.eu/complete/google-oauth2/` must be registered as an authorized redirect URI.

---

## 8. Vault OIDC Authentication (Google)

### 8.1 Enable and Configure OIDC

```bash
# Enable OIDC auth method
oc exec -n vault vault-0 -- vault auth enable oidc

# Configure OIDC with Google
oc exec -n vault vault-0 -- vault write auth/oidc/config \
  oidc_discovery_url="https://accounts.google.com" \
  oidc_client_id="<google-oauth-client-id>.apps.googleusercontent.com" \
  oidc_client_secret="<google-client-secret>" \
  default_role="redhat-user"

# Create OIDC role for Red Hat users (admin for bkaraore@redhat.com only)
oc exec -n vault vault-0 -- vault write auth/oidc/role/redhat-user \
  bound_audiences="<google-oauth-client-id>.apps.googleusercontent.com" \
  allowed_redirect_uris="https://vault.apps.ocp.karaoren.eu/ui/vault/auth/oidc/oidc/callback" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  user_claim="email" \
  policies="admin" \
  oidc_scopes="openid,email,profile" \
  bound_claims='{"hd":"redhat.com","email":"bkaraore@redhat.com"}'
```

> **Google Cloud Console:** The Vault callback URL `https://vault.apps.ocp.karaoren.eu/ui/vault/auth/oidc/oidc/callback` must be registered as an authorized redirect URI.

---

## 9. External Secrets Operator

### 9.1 Operator Installation

```yaml
# File: eso-subscription.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: openshift-external-secrets-operator
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: external-secrets-operator
  namespace: openshift-external-secrets-operator
spec:
  targetNamespaces:
    - openshift-external-secrets-operator
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: openshift-external-secrets-operator
  namespace: openshift-external-secrets-operator
spec:
  channel: stable-v1
  installPlanApproval: Automatic
  name: openshift-external-secrets-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
```

### 9.2 Vault Policy for ESO

```bash
# Create policy allowing ESO to read secrets
oc exec -n vault vault-0 -- vault policy write external-secrets - <<EOF
path "secret/data/*" {
  capabilities = ["read"]
}
EOF

# Create Kubernetes auth role for ESO
oc exec -n vault vault-0 -- vault write auth/kubernetes/role/external-secrets \
  bound_service_account_names=external-secrets \
  bound_service_account_namespaces=external-secrets \
  policies=external-secrets \
  ttl=24h
```

### 9.3 ClusterSecretStore

```yaml
# File: clustersecretstore.yaml
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: vault
spec:
  provider:
    vault:
      server: "http://vault.vault.svc:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "external-secrets"
          serviceAccountRef:
            name: external-secrets
            namespace: external-secrets
```

### 9.4 NetworkPolicy (Allow ESO to reach Vault)

```yaml
# File: networkpolicy-allow-vault-egress.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-vault-egress
  namespace: external-secrets
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: external-secrets
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: vault
          podSelector:
            matchLabels:
              app.kubernetes.io/instance: vault
      ports:
        - protocol: TCP
          port: 8200
  policyTypes:
    - Egress
```

### 9.5 Example ExternalSecret

```yaml
# File: test-externalsecret.yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: vault-test
  namespace: external-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: vault-test-secret
  data:
    - secretKey: username
      remoteRef:
        key: test
        property: username
    - secretKey: password
      remoteRef:
        key: test
        property: password
```

```bash
oc apply -f clustersecretstore.yaml
oc apply -f networkpolicy-allow-vault-egress.yaml
oc apply -f test-externalsecret.yaml

# Verify
oc get clustersecretstore vault
oc get externalsecret vault-test -n external-secrets
oc get secret vault-test-secret -n external-secrets -o jsonpath='{.data}' | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print({k:base64.b64decode(v).decode() for k,v in d.items()})"
```

### 9.6 Vault → OCP Secret Sync (ExternalSecrets)

The following `ExternalSecret` resources sync secrets from Vault to OCP automatically (hourly refresh). Vault is the **single source of truth** — update secrets in Vault and ESO will propagate them to OCP.

```yaml
---
# Portal secrets (aap-portal namespace)
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: secrets-rhaap-portal
  namespace: aap-portal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: secrets-rhaap-portal
    creationPolicy: Orphan
  data:
    - secretKey: aap-host-url
      remoteRef:
        key: aap/portal
        property: aap_host_url
    - secretKey: oauth-client-id
      remoteRef:
        key: aap/portal
        property: oauth_client_id
    - secretKey: oauth-client-secret
      remoteRef:
        key: aap/portal
        property: oauth_client_secret
    - secretKey: aap-token
      remoteRef:
        key: aap/portal
        property: aap_token
---
# SCM tokens (aap-portal namespace)
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: secrets-scm
  namespace: aap-portal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: secrets-scm
    creationPolicy: Orphan
  data:
    - secretKey: github-token
      remoteRef:
        key: aap/scm
        property: github_token
    - secretKey: gitlab-token
      remoteRef:
        key: aap/scm
        property: gitlab_token
---
# Registry pull secret (aap-portal namespace)
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: rhdh-pull-secret
  namespace: aap-portal
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: rhdh-pull-secret
    creationPolicy: Orphan
    template:
      type: kubernetes.io/dockerconfigjson
  data:
    - secretKey: .dockerconfigjson
      remoteRef:
        key: registry/pull-secret
        property: dockerconfigjson
        decodingStrategy: Base64
---
# Let's Encrypt wildcard cert (openshift-ingress namespace)
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: letsencrypt-wildcard
  namespace: openshift-ingress
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: letsencrypt-wildcard
    creationPolicy: Orphan
    template:
      type: kubernetes.io/tls
  data:
    - secretKey: tls.crt
      remoteRef:
        key: letsencrypt/certs
        property: fullchain_b64
        decodingStrategy: Base64
    - secretKey: tls.key
      remoteRef:
        key: letsencrypt/certs
        property: private_key_b64
        decodingStrategy: Base64
---
# Let's Encrypt API cert (openshift-config namespace)
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: letsencrypt-api
  namespace: openshift-config
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault
    kind: ClusterSecretStore
  target:
    name: letsencrypt-api
    creationPolicy: Orphan
    template:
      type: kubernetes.io/tls
  data:
    - secretKey: tls.crt
      remoteRef:
        key: letsencrypt/certs
        property: fullchain_b64
        decodingStrategy: Base64
    - secretKey: tls.key
      remoteRef:
        key: letsencrypt/certs
        property: private_key_b64
        decodingStrategy: Base64
```

**How it works:**
- ESO controller (in `external-secrets` namespace) authenticates to Vault via Kubernetes auth
- Every 1 hour, ESO reads values from Vault and updates the corresponding K8s Secrets
- `creationPolicy: Orphan` — secrets persist even if the ExternalSecret is deleted
- `decodingStrategy: Base64` — used for binary data (certs, pull secrets) stored as base64 in Vault
- To rotate a secret: update it in Vault → ESO syncs within 1 hour (or trigger manually: `oc annotate es <name> -n <ns> force-sync=$(date +%s)`)

**Verify sync status:**

```bash
# Check all ExternalSecrets
oc get externalsecrets -A

# Expected output: all STATUS=SecretSynced, READY=True
# NAMESPACE           NAME                   STATUS         READY
# aap-portal          secrets-rhaap-portal   SecretSynced   True
# aap-portal          secrets-scm            SecretSynced   True
# aap-portal          rhdh-pull-secret       SecretSynced   True
# openshift-ingress   letsencrypt-wildcard   SecretSynced   True
# openshift-config    letsencrypt-api        SecretSynced   True
```

---

## 10. Self-Service Automation Portal

### 10.1 Pre-Installation: AAP OAuth Application

```bash
AAP_GW_POD="aap-gateway-6987568d8c-769jg"
ADMIN_PASS=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)

# Create OAuth Application in AAP
oc exec -n aap ${AAP_GW_POD} -- curl -sk \
  -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "http://localhost:8080/api/gateway/v1/applications/" \
  -d '{
    "name": "Self-Service Automation Portal",
    "organization": 1,
    "client_type": "confidential",
    "authorization_grant_type": "authorization-code",
    "redirect_uris": "https://rhaap-portal-aap-portal.apps.ocp.karaoren.eu/api/auth/rhaap/handler/frame"
  }'

# Enable OAuth token creation for external users
oc exec -n aap ${AAP_GW_POD} -- curl -sk \
  -X PUT \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "http://localhost:8080/api/gateway/v1/settings/oauth2_provider/" \
  -d '{"ALLOW_OAUTH2_FOR_EXTERNAL_USERS": true}'

# Generate AAP admin token for portal
oc exec -n aap ${AAP_GW_POD} -- curl -sk \
  -X POST \
  -H "Content-Type: application/json" \
  -u "admin:${ADMIN_PASS}" \
  "http://localhost:8080/api/gateway/v1/tokens/" \
  -d '{
    "scope": "write",
    "application": 1,
    "description": "Self-Service Portal Token"
  }'
```

### 10.2 OpenShift Project and Secrets

```bash
# Create project
oc new-project aap-portal

# Create AAP authentication secret
oc create secret generic secrets-rhaap-portal \
  --namespace=aap-portal \
  --from-literal=aap-host-url="https://aap-aap.apps.ocp.karaoren.eu" \
  --from-literal=oauth-client-id="<portal-oauth-client-id>" \
  --from-literal=oauth-client-secret="<portal-oauth-client-secret>" \
  --from-literal=aap-token="<aap-portal-token>"

# Create SCM tokens secret (placeholder if no Git tokens available)
oc create secret generic secrets-scm \
  --namespace=aap-portal \
  --from-literal=github-token="placeholder-not-configured" \
  --from-literal=gitlab-token="placeholder-not-configured"

# Create registry auth secret for OCI plugin delivery
oc get secret pull-secret -n openshift-config \
  -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d > /tmp/auth.json

oc create secret generic rhaap-portal-dynamic-plugins-registry-auth \
  --namespace=aap-portal \
  --from-file=auth.json=/tmp/auth.json

rm -f /tmp/auth.json
```

### 10.3 Helm Chart Installation

```yaml
# File: portal-values.yaml
redhat-developer-hub:
  global:
    clusterRouterBase: apps.ocp.karaoren.eu
    # Use OCI mode to pull plugins directly from registry.redhat.io
    pluginMode: oci
```

```bash
# Add the OpenShift Helm chart repo
helm repo add openshift-helm-charts https://charts.openshift.io/

# Install the portal
helm install rhaap-portal openshift-helm-charts/redhat-rhaap-portal \
  --namespace aap-portal \
  -f portal-values.yaml
```

### 10.4 Portal Access

| Component | Value |
|---|---|
| **URL** | https://rhaap-portal-aap-portal.apps.ocp.karaoren.eu |
| **Helm Chart** | `openshift-helm-charts/redhat-rhaap-portal` v2.1.0 |
| **Plugin Mode** | OCI (`registry.redhat.io`) |
| **Auth** | AAP OAuth2 (sign in via AAP credentials) |

---

## Summary of All Deployed Components

| Component | Namespace | Type | Version |
|---|---|---|---|
| OpenShift | - | Cluster | 4.20.14 |
| OpenShift Virtualization (CNV) | openshift-cnv | Operator | stable |
| LVM Storage (LVMS) | openshift-storage | Operator | stable-4.20 |
| NFS Server | nfs-server | Deployment | volume-nfs:0.8 |
| NFS CSI Driver | kube-system | Helm | v4.9.0 (nfs.csi.k8s.io) |
| Ansible Automation Platform | aap | Operator (CR) | 2.6 |
| HashiCorp Vault CE | vault | Helm | 0.32.0 (app 1.21.2) |
| External Secrets Operator | external-secrets | Operator | stable-v1 |
| Self-Service Portal | aap-portal | Helm | 2.1.0 (app 2.1.1) |
| Let's Encrypt TLS | openshift-ingress / openshift-config | acme.sh | E7 (ECC) |

## Summary of Routes / URLs

| Service | URL |
|---|---|
| OpenShift Console | https://console-openshift-console.apps.ocp.karaoren.eu |
| AAP Gateway | https://aap-aap.apps.ocp.karaoren.eu |
| AAP Controller | https://aap-controller-aap.apps.ocp.karaoren.eu |
| AAP EDA | https://aap-eda-aap.apps.ocp.karaoren.eu |
| AAP Hub | https://aap-hub-aap.apps.ocp.karaoren.eu |
| Vault UI | https://vault.apps.ocp.karaoren.eu |
| Self-Service Portal | https://rhaap-portal-aap-portal.apps.ocp.karaoren.eu |

---

## 11. Let's Encrypt TLS Certificates

Custom TLS certificates from Let's Encrypt were configured for the OCP console, API server, AAP WebUI, and all `*.apps` routes.

### 11.1 Certificate Generation (acme.sh)

```bash
# Install acme.sh
curl https://get.acme.sh | sh -s email=bkaraore@redhat.com

# Set name.com API credentials
export Namecom_Username="<namecom-username>"
export Namecom_Token="<name.com API token>"

# Issue wildcard + API certificate using name.com DNS-01 challenge
~/.acme.sh/acme.sh --issue \
  -d "*.apps.ocp.karaoren.eu" \
  -d "api.ocp.karaoren.eu" \
  --dns dns_namecom \
  --server letsencrypt
```

**Certificate details:**
- **Issuer:** Let's Encrypt E7
- **SANs:** `*.apps.ocp.karaoren.eu`, `api.ocp.karaoren.eu`
- **Valid:** Feb 19, 2026 – May 20, 2026
- **Key Type:** ECC (ECDSA P-256)
- **Files location:** `~/.acme.sh/*.apps.ocp.karaoren.eu_ecc/`

### 11.2 Ingress Controller Certificate

```bash
# Create TLS secret in openshift-ingress namespace
oc create secret tls letsencrypt-wildcard \
  --cert="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc/fullchain.cer" \
  --key="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc/*.apps.ocp.karaoren.eu.key" \
  -n openshift-ingress

# Patch the default IngressController to use the new certificate
oc patch ingresscontroller default -n openshift-ingress-operator \
  --type=merge \
  -p='{"spec":{"defaultCertificate":{"name":"letsencrypt-wildcard"}}}'
```

This applies the Let's Encrypt wildcard certificate to all `*.apps.ocp.karaoren.eu` routes, including:
- OCP Console (`console-openshift-console.apps.ocp.karaoren.eu`)
- AAP Gateway (`aap-aap.apps.ocp.karaoren.eu`)
- Vault UI (`vault.apps.ocp.karaoren.eu`)
- Self-Service Portal (`rhaap-portal-aap-portal.apps.ocp.karaoren.eu`)

### 11.3 API Server Certificate

```bash
# Create TLS secret in openshift-config namespace
oc create secret tls letsencrypt-api \
  --cert="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc/fullchain.cer" \
  --key="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc/*.apps.ocp.karaoren.eu.key" \
  -n openshift-config

# Patch the API server to use the named certificate for api.ocp.karaoren.eu
oc patch apiserver cluster \
  --type=merge \
  -p='{"spec":{"servingCerts":{"namedCertificates":[{"names":["api.ocp.karaoren.eu"],"servingCertificate":{"name":"letsencrypt-api"}}]}}}'
```

### 11.4 Kubeconfig Update

After applying the Let's Encrypt certificate to the API server, the kubeconfig's embedded `certificate-authority-data` (which referenced the old internal OCP CA) was removed so the `oc` client uses the system CA trust store instead:

```bash
# Remove embedded CA data from kubeconfig
perl -i -ne 'print unless /^\s+certificate-authority-data:/' ~/.kube/config
```

### 11.5 Certificate Renewal

`acme.sh` automatically sets up a cron job for certificate renewal. After renewal, update the cert in Vault and ESO will sync it to OCP:

```bash
# Renew certificates (automated via cron, or manually)
~/.acme.sh/acme.sh --renew -d "*.apps.ocp.karaoren.eu" -d "api.ocp.karaoren.eu"

# Update the cert in Vault — ESO will auto-sync to OCP within 1 hour
CERT_DIR="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc"
VT="<vault-root-token>"
KEY_B64=$(cat "$CERT_DIR"/*.apps.ocp.karaoren.eu.key | base64)
CHAIN_B64=$(cat "$CERT_DIR"/fullchain.cer | base64)
CA_B64=$(cat "$CERT_DIR"/ca.cer | base64)

oc exec -n vault vault-0 -- sh -c "VAULT_TOKEN='$VT' vault kv put secret/letsencrypt/certs \
  domain='*.apps.ocp.karaoren.eu' alt_domain='api.ocp.karaoren.eu' \
  private_key_b64='$KEY_B64' fullchain_b64='$CHAIN_B64' ca_b64='$CA_B64'"

# (Optional) Force immediate sync instead of waiting 1 hour
oc annotate es letsencrypt-wildcard -n openshift-ingress force-sync=$(date +%s) --overwrite
oc annotate es letsencrypt-api -n openshift-config force-sync=$(date +%s) --overwrite
```

---

## 12. Centralized Secrets in Vault

All secrets are stored in HashiCorp Vault under organized paths. No sensitive values are kept outside Vault.

### 12.1 Vault Secret Structure

| Vault Path | Contents | Used By |
|---|---|---|
| `secret/ocp/google-oauth` | Google OAuth Client ID & Secret | OCP OAuth (RedHatSSO), AAP, Vault OIDC |
| `secret/ocp/slack` | Slack webhook URL & channel | Alertmanager |
| `secret/ocp/aap-gateway-oauth` | AAP OAuthClient name & secret | OCP ↔ AAP OAuth integration |
| `secret/aap/admin` | AAP admin username & password | AAP Gateway login |
| `secret/aap/portal` | Portal OAuth ID, Secret, AAP host URL, AAP token | Self-Service Portal (RHAAP) |
| `secret/vault/tokens` | Root token, unseal key, AAP service token | Vault administration |
| `secret/letsencrypt/certs` | Private key, fullchain, CA cert (base64) | OCP Ingress & API TLS |
| `secret/registry/pull-secret` | `dockerconfigjson` for `registry.redhat.io` (base64) | Portal OCI plugin pulls |
| `secret/dns/namecom` | name.com API username & token | Certificate renewal (acme.sh) |

### 12.2 Retrieving Secrets from Vault

```bash
# Set Vault token
export VAULT_TOKEN="$(vault kv get -field=root_token secret/vault/tokens)"

# Example: Get AAP admin password
vault kv get -field=password secret/aap/admin

# Example: Get Google OAuth Client ID
vault kv get -field=client_id secret/ocp/google-oauth

# Example: Get Let's Encrypt private key (decode from base64)
vault kv get -field=private_key_b64 secret/letsencrypt/certs | base64 -d

# Example: Get pull secret JSON (decode from base64)
vault kv get -field=dockerconfigjson_b64 secret/registry/pull-secret | base64 -d

# Via oc exec (from outside the cluster)
oc exec -n vault vault-0 -- sh -c \
  "VAULT_TOKEN='<root_token>' vault kv get -field=password secret/aap/admin"
```

### 12.3 Script to Store All Secrets

```bash
#!/bin/bash
# store-all-secrets-in-vault.sh
# Collects all cluster secrets and stores them in Vault

VT="<vault-root-token>"
VAULT_CMD="oc exec -n vault vault-0 -- sh -c"

# Google OAuth
GOOGLE_ID=$(oc get oauth cluster -o jsonpath='{.spec.identityProviders[?(@.name=="RedHatSSO")].google.clientID}')
GOOGLE_SECRET_NAME=$(oc get oauth cluster -o jsonpath='{.spec.identityProviders[?(@.name=="RedHatSSO")].google.clientSecret.name}')
GOOGLE_SECRET=$(oc get secret "$GOOGLE_SECRET_NAME" -n openshift-config -o jsonpath='{.data.clientSecret}' | base64 -d)
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/ocp/google-oauth client_id='$GOOGLE_ID' client_secret='$GOOGLE_SECRET'"

# Slack
SLACK_URL="<slack-webhook-url>"
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/ocp/slack webhook_url='$SLACK_URL' channel='#alerts-ocp-karaoren'"

# AAP OAuthClient
AAP_OAUTH=$(oc get oauthclient aap-gateway -o jsonpath='{.secret}')
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/ocp/aap-gateway-oauth client_name='aap-gateway' client_secret='$AAP_OAUTH'"

# AAP Admin
AAP_PW=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/aap/admin username='admin' password='$AAP_PW'"

# Portal
P_HOST=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.aap-host-url}' | base64 -d)
P_OID=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.oauth-client-id}' | base64 -d)
P_OSEC=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.oauth-client-secret}' | base64 -d)
P_TOK=$(oc get secret secrets-rhaap-portal -n aap-portal -o jsonpath='{.data.aap-token}' | base64 -d)
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/aap/portal aap_host_url='$P_HOST' oauth_client_id='$P_OID' oauth_client_secret='$P_OSEC' aap_token='$P_TOK'"

# Let's Encrypt certs (base64 encoded)
CERT_DIR="$HOME/.acme.sh/*.apps.ocp.karaoren.eu_ecc"
KEY_B64=$(cat "$CERT_DIR"/*.apps.ocp.karaoren.eu.key | base64)
CHAIN_B64=$(cat "$CERT_DIR"/fullchain.cer | base64)
CA_B64=$(cat "$CERT_DIR"/ca.cer | base64)
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/letsencrypt/certs domain='*.apps.ocp.karaoren.eu' alt_domain='api.ocp.karaoren.eu' private_key_b64='$KEY_B64' fullchain_b64='$CHAIN_B64' ca_b64='$CA_B64'"

# Pull secret
PS_B64=$(oc get secret rhdh-pull-secret -n aap-portal -o jsonpath='{.data.\.dockerconfigjson}')
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/registry/pull-secret registry='registry.redhat.io' dockerconfigjson_b64='$PS_B64'"

# DNS provider
$VAULT_CMD "VAULT_TOKEN='$VT' vault kv put secret/dns/namecom username='<namecom-user>' api_token='<namecom-token>'"
```

---

## Credentials Reference

All credentials are now stored in Vault. Use the commands below to retrieve them:

| Credential | Vault Path | Field | Synced to OCP via ESO? |
|---|---|---|---|
| AAP admin password | `secret/aap/admin` | `password` | ❌ (operator-managed) |
| Vault Root Token | `secret/vault/tokens` | `root_token` | ❌ (Vault internal) |
| Vault Unseal Key | `secret/vault/tokens` | `unseal_key` | ❌ (Vault internal) |
| Vault AAP Service Token | `secret/vault/tokens` | `aap_service_token` | ❌ (Vault internal) |
| Google OAuth Client ID | `secret/ocp/google-oauth` | `client_id` | ❌ (OAuth config ref) |
| Google OAuth Client Secret | `secret/ocp/google-oauth` | `client_secret` | ❌ (OAuth config ref) |
| Slack Webhook URL | `secret/ocp/slack` | `webhook_url` | ❌ (Alertmanager config) |
| AAP Gateway OAuthClient Secret | `secret/ocp/aap-gateway-oauth` | `client_secret` | ❌ (OAuthClient CRD) |
| Portal OAuth Client ID | `secret/aap/portal` | `oauth_client_id` | ✅ → `secrets-rhaap-portal` (aap-portal) |
| Portal OAuth Client Secret | `secret/aap/portal` | `oauth_client_secret` | ✅ → `secrets-rhaap-portal` (aap-portal) |
| Portal AAP Token | `secret/aap/portal` | `aap_token` | ✅ → `secrets-rhaap-portal` (aap-portal) |
| SCM GitHub Token | `secret/aap/scm` | `github_token` | ✅ → `secrets-scm` (aap-portal) |
| SCM GitLab Token | `secret/aap/scm` | `gitlab_token` | ✅ → `secrets-scm` (aap-portal) |
| Registry Pull Secret | `secret/registry/pull-secret` | `dockerconfigjson` | ✅ → `rhdh-pull-secret` (aap-portal) |
| Let's Encrypt Certs | `secret/letsencrypt/certs` | `fullchain_b64`, `private_key_b64` | ✅ → `letsencrypt-wildcard` (openshift-ingress) |
| Let's Encrypt API Certs | `secret/letsencrypt/certs` | `fullchain_b64`, `private_key_b64` | ✅ → `letsencrypt-api` (openshift-config) |
| name.com API Token | `secret/dns/namecom` | `api_token` | ❌ (local acme.sh only) |

> ✅ **Vault is the single source of truth.** Secrets marked with ✅ are automatically synced to OCP via the External Secrets Operator (ESO) every hour. To rotate a secret, update it in Vault and ESO will propagate the change. Secrets marked ❌ are stored in Vault as a backup/reference but are managed by their respective operators or CRDs in OCP.

---

## 13. GitOps Deployment (ArgoCD)

All cluster configuration has been extracted into declarative YAML files under `gitops/` for reproducible, from-scratch deployment using OpenShift GitOps (ArgoCD).

### 13.1 Directory Structure

```
gitops/
├── bootstrap/                        # Bootstrap scripts
│   ├── bootstrap.sh                  # Master bootstrap (run first)
│   └── generate-certs.sh             # Let's Encrypt cert generation
├── cluster/                          # Cluster-level configuration
│   ├── base/                         # Namespaces
│   ├── monitoring/                   # Alertmanager + cluster monitoring
│   ├── oauth/                        # OAuth (GitHub, Google/RedHatSSO)
│   └── certificates/                 # IngressController + APIServer TLS
├── operators/                        # OLM Subscriptions
│   ├── cnv/                          # OpenShift Virtualization
│   ├── lvms/                         # LVM Storage
│   ├── aap/                          # Ansible Automation Platform
│   └── eso/                          # External Secrets Operator
├── storage/                          # Storage infrastructure
│   ├── nfs-server/                   # NFS server deployment
│   └── storageclasses/               # NFS StorageClass + VolumeSnapshotClass
├── apps/                             # Application deployments
│   ├── vault/                        # Vault Helm values + config scripts
│   ├── aap-instance/                 # AAP CR + config script
│   ├── aap-portal/                   # Portal Helm values
│   ├── aap-exec-node/               # Execution node VM + services + config
│   └── cert-renewal/                 # Certificate renewal AAP resources
├── secrets/                          # Secret management
│   ├── vault-config/                 # ClusterSecretStore + NetworkPolicy
│   └── external-secrets/             # ExternalSecret resources
└── argocd/                           # ArgoCD operator + Applications
    ├── gitops-subscription.yaml      # OpenShift GitOps operator
    ├── cluster-role.yaml             # ArgoCD cluster-admin binding
    ├── appproject.yaml               # AppProject definition
    └── applications/                 # 11 ArgoCD Application manifests
        ├── 01-cluster-base.yaml
        ├── 02-operators.yaml
        ├── 03-monitoring.yaml
        ├── 04-storage.yaml
        ├── 05-vault.yaml
        ├── 06-oauth.yaml
        ├── 07-vault-eso-config.yaml
        ├── 08-external-secrets.yaml
        ├── 09-aap.yaml
        ├── 10-certificates.yaml
        └── 11-portal.yaml
```

### 13.2 Deployment Order (Sync Waves)

| Wave | Component | Type | What It Does |
|------|-----------|------|-------------|
| 1 | Namespaces | Kustomize | Creates all namespaces |
| 2 | Operators | Kustomize | Installs CNV, LVMS, AAP, ESO operators |
| 3 | Monitoring | Kustomize | Enables user workload monitoring |
| 4 | Storage | Kustomize + Helm | NFS server, CSI driver, StorageClasses |
| 5 | Vault | Kustomize + Helm | Vault CE with SNO-compatible values |
| 6 | OAuth | Kustomize | OCP OAuth (GitHub + Google/RedHatSSO) |
| 7 | Vault-ESO | Kustomize | ClusterSecretStore + NetworkPolicy |
| 8 | ExternalSecrets | Kustomize | Vault → OCP secret sync |
| 9 | AAP Instance | Kustomize | AAP CR (Controller, EDA, Hub) |
| 10 | Certificates | Kustomize | Let's Encrypt TLS for Ingress + API |
| 11 | Portal | Kustomize + Helm | Self-Service Automation Portal |

### 13.3 How to Deploy from Scratch

```bash
# 1. Push this repo to your Git provider
git remote add origin https://github.com/YOUR_ORG/aap-ocp-karaoren.git
git push -u origin main

# 2. Log in to OCP cluster
oc login https://api.ocp.karaoren.eu:6443 -u kubeadmin -p <password>

# 3. Run the bootstrap script
export GIT_REPO_URL="https://github.com/YOUR_ORG/aap-ocp-karaoren.git"
./gitops/bootstrap/bootstrap.sh

# 4. Follow the manual steps printed by the bootstrap script:
#    - Initialize and unseal Vault
#    - Run configure-vault.sh
#    - Generate Let's Encrypt certs
#    - Store all secrets in Vault
#    - Apply Alertmanager config
#    - Run configure-aap.sh
#    - Register Google OAuth callback URLs
```

### 13.4 What GitOps Manages vs. Manual Steps

| Managed by ArgoCD (GitOps) | Manual Steps Required |
|---|---|
| All namespaces | Vault init + unseal |
| Operator subscriptions (CNV, LVMS, AAP, ESO) | Vault configuration (policies, OIDC) |
| NFS server + CSI driver + StorageClasses | Vault secret population |
| Vault Helm deployment | AAP post-install (OAuth app, authenticator) |
| OAuth configuration | Alertmanager secret (from Vault) |
| ClusterSecretStore + NetworkPolicy | Let's Encrypt cert generation (acme.sh) |
| ExternalSecret resources | Google Cloud Console callback URLs |
| AAP custom resource | OAuth secrets in openshift-config |
| IngressController + APIServer TLS config | NFS server SCC grant |
| Self-Service Portal Helm deployment | |

> **Note:** Vault and the Self-Service Portal are deployed via Helm charts managed by ArgoCD. Vault requires manual initialization/unsealing after deployment. The AAP OAuth application and authenticator maps must be configured via the AAP API after the AAP instance is running.

---

## 14. Ansible Playbooks (Alternative to Shell Scripts)

All shell scripts in the `gitops/` directory have corresponding Ansible playbook equivalents in the `ansible/` directory, providing better idempotency, structured error handling, and secrets management.

### 14.1 Directory Structure

```
ansible/
├── ansible.cfg                    # Ansible configuration
├── requirements.yml               # Collection dependencies (kubernetes.core)
├── inventory/
│   └── localhost.yml              # Localhost inventory
├── vars/
│   ├── main.yml                   # Centralized variables (non-sensitive)
│   └── secrets.yml.example        # Template for secrets (encrypt with ansible-vault)
└── playbooks/
    ├── site.yml                   # Master playbook — runs all phases in order
    ├── bootstrap.yml              # Phase 1: GitOps operator + ArgoCD Apps
    ├── configure-vault.yml        # Phase 2: Vault policies, auth, OIDC
    ├── generate-certs.yml         # Phase 3: Let's Encrypt certs via acme.sh
    ├── store-secrets.yml          # Phase 4: Populate Vault with all secrets
    ├── configure-aap.yml          # Phase 5: AAP authenticator, OAuth app, portal token
    ├── setup-cert-renewal-job.yml # Phase 6: AAP cert renewal JT + schedule + K8s credential
    ├── renew-certificates.yml     # Cert renewal (runs in AAP scheduled job or manually)
    └── configure-exec-node.yml    # Phase 7: RHEL 9 VM as AAP execution node
```

### 14.2 Shell → Ansible Mapping

| Shell Script | Ansible Playbook | Key Improvements |
|---|---|---|
| `gitops/bootstrap/bootstrap.sh` | `ansible/playbooks/bootstrap.yml` | Uses `kubernetes.core.k8s` module, retry loops with `until` |
| `gitops/bootstrap/generate-certs.sh` | `ansible/playbooks/generate-certs.yml` | `ansible.builtin.stat` for idempotent acme.sh install |
| `gitops/apps/vault/configure-vault.sh` | `ansible/playbooks/configure-vault.yml` | Structured policy creation, `no_log` for secrets |
| `gitops/apps/vault/store-secrets-in-vault.sh` | `ansible/playbooks/store-secrets.yml` | `ansible.builtin.slurp` for cert reading, `no_log` throughout |
| `gitops/apps/aap-instance/configure-aap.sh` | `ansible/playbooks/configure-aap.yml` | `ansible.builtin.uri` instead of curl, proper JSON parsing |

### 14.3 Prerequisites

```bash
# Install Ansible (if not already installed)
pip3 install ansible

# Install required collections
cd ansible/
ansible-galaxy collection install -r requirements.yml
```

### 14.4 Secrets Management

```bash
# Copy the example secrets file and fill in values
cp vars/secrets.yml.example vars/secrets.yml
vi vars/secrets.yml

# Encrypt with ansible-vault
ansible-vault encrypt vars/secrets.yml
```

**`vars/secrets.yml`** contains:
| Variable | Description |
|---|---|
| `vault_root_token` | Vault root token (from `vault operator init`) |
| `vault_unseal_key` | Vault unseal key |
| `google_client_secret` | Google OAuth2 client secret |
| `github_client_secret` | GitHub OAuth client secret |
| `slack_webhook_url` | Slack incoming webhook URL |
| `namecom_username` | name.com API username |
| `namecom_api_token` | name.com API token |

### 14.5 Usage

```bash
cd ansible/

# ── Run everything (full deployment) ──
ansible-playbook playbooks/site.yml -e @vars/secrets.yml --ask-vault-pass

# ── Run individual phases ──
# Phase 1: Bootstrap GitOps
ansible-playbook playbooks/bootstrap.yml \
  -e git_repo_url=https://github.com/bkaraoren/ocp_lab_aap.git

# Phase 2: Configure Vault (after manual init + unseal)
ansible-playbook playbooks/configure-vault.yml \
  -e @vars/secrets.yml --ask-vault-pass

# Phase 3: Generate Let's Encrypt certificates
ansible-playbook playbooks/generate-certs.yml \
  -e @vars/secrets.yml --ask-vault-pass

# Phase 4: Store all secrets in Vault
ansible-playbook playbooks/store-secrets.yml \
  -e @vars/secrets.yml --ask-vault-pass

# Phase 5: Configure AAP (after AAP pods are Running)
ansible-playbook playbooks/configure-aap.yml \
  -e @vars/secrets.yml --ask-vault-pass

# Phase 6: Setup automated certificate renewal
ansible-playbook playbooks/setup-cert-renewal-job.yml \
  -e @vars/secrets.yml --ask-vault-pass

# Phase 7: Configure AAP Execution Node (RHEL 9 VM)
ansible-playbook playbooks/configure-exec-node.yml

# ── Run with tags (selective execution) ──
ansible-playbook playbooks/site.yml -e @vars/secrets.yml --ask-vault-pass \
  --tags vault,secrets
```

### 14.6 Key Improvements over Shell Scripts

| Feature | Shell Scripts | Ansible Playbooks |
|---|---|---|
| **Idempotency** | Partial (manual checks) | Built-in (`kubernetes.core.k8s`, `creates:`) |
| **Secrets handling** | Printed to stdout | `no_log: true` suppresses sensitive output |
| **API calls** | `curl` with string parsing | `ansible.builtin.uri` with structured JSON |
| **Error handling** | `set -euo pipefail` | Per-task `failed_when`, `retries`, `until` |
| **K8s resources** | `oc apply -f` | `kubernetes.core.k8s` module (native) |
| **Variables** | Env vars, hardcoded | Centralized `vars/main.yml` + vault-encrypted secrets |
| **Selective runs** | Not supported | Tags: `--tags bootstrap,vault,certs,secrets,aap,cert-renewal,exec-node` |
| **Reusability** | Copy/paste | `import_playbook`, roles-ready structure |

---

## 15. Automated Certificate Renewal (AAP Scheduled Job)

Let's Encrypt certificates expire after **90 days**. An AAP scheduled job runs every **60 days** (30-day safety margin) to automatically renew them, update Vault, and trigger ESO to sync the new certs to OCP.

### 15.1 Architecture

```
Schedule (every 60 days) → Job Template → renew-certificates.yml
  → acme.sh --renew (DNS-01 via name.com)
  → Vault kv put secret/letsencrypt/certs (updated certs)
  → ESO ExternalSecret refresh (annotate to force sync)
  → OCP secrets updated (letsencrypt-wildcard, letsencrypt-api)
  → IngressController + APIServer pick up new certs automatically
```

### 15.2 AAP Resources Created

| Resource | Name | ID |
|---|---|---|
| Custom Credential Type | `Let's Encrypt Renewal Credentials` | 32 |
| Credential (custom) | `LE Renewal - name.com + Vault` | 3 |
| Credential (K8s) | `OCP Cluster - cert-renewal SA` | 4 |
| Project | `OCP Lab - Certificate Management` | 10 |
| Inventory | `Localhost` | 2 |
| Job Template | `Renew Let's Encrypt Certificates` | 11 |
| Schedule | `Every 60 days - Certificate Renewal` | 6 |

### 15.3 Custom Credential Type

Injects three extra vars into the playbook:

| Field | Type | Description |
|---|---|---|
| `namecom_username` | string | name.com API username |
| `namecom_api_token` | string (secret) | name.com API token |
| `vault_root_token` | string (secret) | Vault root token for updating certs |

### 15.4 Schedule Details

```
RRULE: DTSTART:20260223T020000Z RRULE:FREQ=DAILY;INTERVAL=60
```

- **Frequency:** Every 60 days
- **Start:** February 23, 2026 at 02:00 UTC
- **Next run:** April 24, 2026 at 02:00 UTC
- **Safety margin:** 30 days before cert expiry (90 - 60 = 30)

### 15.5 OCP ServiceAccount for AAP EE

The AAP Execution Environment (EE) needs cluster access to read/write secrets and interact with Vault. A dedicated ServiceAccount with `cluster-admin` is created:

```yaml
# ServiceAccount + ClusterRoleBinding + long-lived token
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-renewal
  namespace: aap
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-renewal-cluster-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: cert-renewal
  namespace: aap
---
apiVersion: v1
kind: Secret
metadata:
  name: cert-renewal-token
  namespace: aap
  annotations:
    kubernetes.io/service-account.name: cert-renewal
type: kubernetes.io/service-account-token
```

An "OpenShift or Kubernetes API Bearer Token" credential (type 17) is created in AAP using this SA token, and associated with the Job Template. The playbook automatically logs in using the injected `K8S_AUTH_HOST` and `K8S_AUTH_API_KEY` environment variables.

### 15.6 Current Certificate Status

```
Certificate: *.apps.ocp.karaoren.eu + api.ocp.karaoren.eu
Issuer:      Let's Encrypt (E7)
Not Before:  Feb 23 15:31:01 2026 GMT
Not After:   May 24 15:31:00 2026 GMT
Serial:      <certificate-serial>
```

Last renewed: February 23, 2026 (tested successfully via AAP Job Template)

### 15.7 Renewal Playbook

`ansible/playbooks/renew-certificates.yml` — performs the full renewal cycle:

1. Installs `acme.sh` if not present
2. Renews certificates via DNS-01 challenge (name.com API)
3. Reads the new cert files (key, fullchain, CA)
4. Updates `secret/letsencrypt/certs` in Vault
5. Annotates ESO ExternalSecrets to force immediate refresh
6. Verifies new certs are active in OCP

### 15.8 Manual Run

```bash
# From AAP UI:
#   Templates → "Renew Lets Encrypt Certificates" → Launch

# From CLI (Ansible):
cd ansible/
ansible-playbook playbooks/renew-certificates.yml \
  -e namecom_username=<user> \
  -e namecom_api_token=<token> \
  -e vault_root_token=<token>
```

### 15.9 Setup Playbook

`ansible/playbooks/setup-cert-renewal-job.yml` creates all the AAP resources above automatically:

```bash
cd ansible/
ansible-playbook playbooks/setup-cert-renewal-job.yml \
  -e @vars/secrets.yml --ask-vault-pass
```

### 15.10 AAP Resources Summary

| Resource | Name | ID |
|---|---|---|
| Custom Credential Type | `Let's Encrypt Renewal Credentials` | 32 |
| Credential (custom) | `LE Renewal - name.com + Vault` | 3 |
| Credential (K8s) | `OCP Cluster - cert-renewal SA` | 4 |
| Project | `OCP Lab - Certificate Management` | 10 |
| Inventory | `Localhost` | 2 |
| Job Template | `Renew Let's Encrypt Certificates` | 11 |
| Schedule | `Every 60 days - Certificate Renewal` | 6 |

### 15.11 Resource Operator CRs (GitOps)

GitOps-managed YAML files are available at `gitops/apps/cert-renewal/`:

```
gitops/apps/cert-renewal/
├── connection-secret.yaml    # AAP connection secret
├── service-account.yaml      # ServiceAccount + RBAC + token for EE cluster access
├── project.yaml              # AnsibleProject CR
├── job-template.yaml         # JobTemplate CR
├── schedule.yaml             # AnsibleSchedule CR (60-day RRULE)
└── kustomization.yaml
```

### 15.12 Tested Renewal Flow (Verified Feb 23, 2026)

```
Before renewal:
  notBefore = Feb 19 10:32:09 2026 GMT
  notAfter  = May 20 10:32:08 2026 GMT
  serial    = <old-certificate-serial>

After renewal (AAP Job ID: 16):
  notBefore = Feb 23 15:31:01 2026 GMT
  notAfter  = May 24 15:31:00 2026 GMT
  serial    = <new-certificate-serial>

Verified:
  ✅ acme.sh installed in EE (--force --nocron for containerized environments)
  ✅ DNS-01 challenge via name.com API (TXT records auto-created/verified/cleaned)
  ✅ Vault updated at secret/letsencrypt/certs
  ✅ ESO ExternalSecrets force-synced
  ✅ OCP secrets updated (openshift-ingress + openshift-config)
  ✅ New certs served by IngressController and APIServer
```

### 15.13 Key Lessons from Testing

1. **EE has no cron** — `acme.sh` install requires `--force --nocron` flags
2. **EE has no kubeconfig** — K8s credential (type 17) injects `K8S_AUTH_HOST`/`K8S_AUTH_API_KEY`; playbook uses `oc login` with these
3. **First run uses `--issue`** — subsequent runs use `--renew --force`; playbook auto-detects
4. **DNS hooks must be included** — downloading the full tarball (not just `acme.sh` script) is required for `dns_namecom` support

---

## 16. AAP Execution Node (RHEL 9 VM)

A RHEL 9 virtual machine is provisioned on OpenShift Virtualization and configured as an external execution node for the AAP controller. This allows AAP to run Ansible jobs on a dedicated VM outside the OCP pod-based execution environment.

### 16.1 Architecture

```
┌─────────────────────────────────────────────────────┐
│                   OCP Cluster (SNO)                  │
│                                                      │
│  ┌──────────────────┐    ┌────────────────────────┐ │
│  │   AAP Controller  │    │  aap-exec namespace     │ │
│  │   (aap namespace)  │    │  ┌──────────────────┐  │ │
│  │                    │    │  │ RHEL 9 VM         │  │ │
│  │  receptor (ctrl)  ├──TCP──►│  receptor (exec)  │  │ │
│  │  port: varies     │:27199│  │  port: 27199     │  │ │
│  │                    │    │  │  ansible-runner   │  │ │
│  │  TLS mutual auth  │    │  │  podman            │  │ │
│  └──────────────────┘    │  └──────────────────┘  │ │
│                          │                         │ │
│                          │  Service: aap-exec-node │ │
│                          │  ClusterIP:27199        │ │
│                          └────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### 16.2 VM Specifications

| Property | Value |
|----------|-------|
| **Name** | `aap-exec-node` |
| **Namespace** | `aap-exec` |
| **OS** | Red Hat Enterprise Linux 9.7 (Plow) |
| **vCPUs** | 4 |
| **RAM** | 8 GiB |
| **Disk** | 40 GiB (LVMS `lvms-vm-vg1`) |
| **Boot Source** | `rhel9` DataSource (auto-cloned from `openshift-virtualization-os-images`) |
| **Network** | Masquerade (pod network) |
| **Cloud-init** | SSH key, hostname, podman |

### 16.3 Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aap-exec
  labels:
    openshift.io/cluster-monitoring: "true"
```

### 16.4 VirtualMachine CR

```yaml
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: aap-exec-node
  namespace: aap-exec
  labels:
    app: aap-exec-node
spec:
  runStrategy: Always
  template:
    metadata:
      labels:
        app: aap-exec-node
        kubevirt.io/domain: aap-exec-node
    spec:
      domain:
        cpu:
          cores: 4
        memory:
          guest: 8Gi
        devices:
          disks:
            - name: rootdisk
              disk:
                bus: virtio
            - name: cloudinit
              disk:
                bus: virtio
          interfaces:
            - name: default
              masquerade: {}
        machine:
          type: q35
      networks:
        - name: default
          pod: {}
      volumes:
        - name: rootdisk
          dataVolume:
            name: aap-exec-node-rootdisk
        - name: cloudinit
          cloudInitNoCloud:
            userData: |
              #cloud-config
              hostname: aap-exec-node
              user: cloud-user
              ssh_authorized_keys:
                - <SSH_PUBLIC_KEY>
              chpasswd:
                expire: false
              packages:
                - python3
                - python3-pip
                - podman
              runcmd:
                - systemctl enable --now podman.socket
  dataVolumeTemplates:
    - metadata:
        name: aap-exec-node-rootdisk
      spec:
        pvc:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 40Gi
          storageClassName: lvms-vm-vg1
        source:
          pvc:
            namespace: openshift-virtualization-os-images
            name: rhel9-ab4ec16077fe
```

### 16.5 Services (Receptor + SSH)

```yaml
# ClusterIP service for receptor mesh connectivity
apiVersion: v1
kind: Service
metadata:
  name: aap-exec-node
  namespace: aap-exec
spec:
  type: ClusterIP
  selector:
    kubevirt.io/domain: aap-exec-node
  ports:
    - port: 27199
      targetPort: 27199
      protocol: TCP
      name: receptor
```

### 16.6 RHEL Repo Configuration (Entitlements)

Since the VM is not registered with `subscription-manager`, RHEL repos are configured using the cluster's entitlement certificates:

```bash
# Extract entitlements from the OCP cluster
oc get secret etc-pki-entitlement -n openshift-config-managed -o jsonpath='{.data}'

# Place certificates at:
#   /etc/pki/entitlement/entitlement.pem
#   /etc/pki/entitlement/entitlement-key.pem

# Repos configured:
#   - rhel-9-baseos (cdn.redhat.com)
#   - rhel-9-appstream (cdn.redhat.com)
#   - ansible-automation-platform-2.6-for-rhel-9-x86_64-rpms (cdn.redhat.com)
```

### 16.7 Packages Installed

```bash
sudo dnf install -y receptor ansible-runner podman python3 python3-pip
# receptor:       1.6.3
# ansible-runner: 2.4.2
# podman:         5.6.0
```

### 16.8 Register Execution Node in AAP

```bash
AAP_GW=$(oc get route aap -n aap -o jsonpath='{.spec.host}')
AAP_PW=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)

# Create the execution node instance
curl -sk -u "admin:${AAP_PW}" \
  -X POST -H "Content-Type: application/json" \
  "https://${AAP_GW}/api/controller/v2/instances/" \
  -d '{
    "hostname": "aap-exec-node.aap-exec.svc.cluster.local",
    "node_type": "execution",
    "listener_port": 27199,
    "peers_from_control_nodes": true
  }'

# Download the install bundle (contains receptor TLS certs and Ansible playbook)
curl -sk -u "admin:${AAP_PW}" \
  "https://${AAP_GW}/api/controller/v2/instances/<INSTANCE_ID>/install_bundle/" \
  -o /tmp/aap-exec-bundle.tar.gz
```

### 16.9 Install Bundle Contents

The install bundle generated by AAP contains:

```
*_install_bundle/
├── receptor/
│   ├── tls/
│   │   ├── ca/mesh-CA.crt      # Receptor mesh CA certificate
│   │   ├── receptor.crt         # Node TLS certificate
│   │   └── receptor.key         # Node TLS private key
│   └── work_public_key.pem      # Work signature verification key
├── install_receptor.yml          # Ansible playbook
├── inventory.yml                 # Ansible inventory (needs updating)
├── group_vars/all.yml            # Receptor role variables
└── requirements.yml              # ansible.receptor collection
```

The playbook is run against the VM using `virtctl port-forward` for SSH access:

```bash
# Port-forward SSH
virtctl port-forward -n aap-exec vm/aap-exec-node 2222:22 &

# Update inventory to use port-forward
# Then run:
ansible-galaxy collection install -r requirements.yml --force --ignore-certs
ansible-playbook -i inventory.yml install_receptor.yml -v
```

### 16.10 Receptor Configuration

After the install bundle runs, the receptor config must be corrected (the bundle uses `ansible_host` as the node ID, which is `127.0.0.1` when using port-forward):

```yaml
# /etc/receptor/receptor.conf (final corrected version)
---
- node:
    id: aap-exec-node.aap-exec.svc.cluster.local

- work-verification:
    publickey: /etc/receptor/work_public_key.pem

- log-level: info

- control-service:
    service: control
    filename: /var/run/receptor/receptor.sock
    permissions: "0660"

- tls-server:
    name: tls_server
    cert: /etc/receptor/tls/receptor.crt
    key: /etc/receptor/tls/receptor.key
    clientcas: /etc/receptor/tls/ca/mesh-CA.crt
    requireclientcert: true
    mintls13: false

- tls-client:
    name: tls_client
    cert: /etc/receptor/tls/receptor.crt
    key: /etc/receptor/tls/receptor.key
    rootcas: /etc/receptor/tls/ca/mesh-CA.crt
    insecureskipverify: false
    mintls13: false

- tcp-listener:
    port: 27199
    tls: tls_server

- work-command:
    worktype: ansible-runner
    command: ansible-runner
    params: worker
    allowruntimeparams: true
    verifysignature: true
```

> **Critical:** The `worktype` must be `ansible-runner` (not `local`). Using `local` causes the error `work type did not expect a signature` because the controller sends signed work, and the work type name must match what the controller expects.

### 16.11 Receptor Systemd Service

```ini
# /etc/systemd/system/receptor.service
[Unit]
Description=Receptor
After=network.target

[Service]
User=awx
Group=awx
ExecStart=/usr/bin/receptor --config /etc/receptor/receptor.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RuntimeDirectory=receptor
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
```

### 16.12 Add to Instance Group

```bash
# Add execution node to the "default" instance group
curl -sk -u "admin:${AAP_PW}" \
  -X POST -H "Content-Type: application/json" \
  "https://${AAP_GW}/api/controller/v2/instance_groups/2/instances/" \
  -d '{"id": <INSTANCE_ID>}'

# Trigger health check
curl -sk -u "admin:${AAP_PW}" \
  -X POST "https://${AAP_GW}/api/controller/v2/instances/<INSTANCE_ID>/health_check/"
```

### 16.13 Final Status

| Property | Value |
|----------|-------|
| **Hostname** | `aap-exec-node.aap-exec.svc.cluster.local` |
| **Node Type** | execution |
| **State** | ✅ ready |
| **Receptor** | 1.6.3 |
| **ansible-runner** | 2.4.2 |
| **Capacity** | 76 |
| **CPU** | 4.0 |
| **Memory** | 8053932032 (≈ 7.5 GiB) |
| **Instance Group** | default |
| **Secure Work Type** | `ansible-runner` |

### 16.14 Receptor Mesh Topology

```
Controller (aap-controller-task-*)  ←──TLS/TCP:27199──→  Execution Node (aap-exec-node)
  node_type: control                                        node_type: execution
  state: ready                                              state: ready
  work types: local, kubernetes-runtime-auth,               secure work types: ansible-runner
              kubernetes-incluster-auth
```

### 16.15 Key Lessons

1. **Worktype must be `ansible-runner`** — Using `local` causes `work type did not expect a signature` because AAP expects the work type name to match the registered work command.
2. **`work-verification` must come BEFORE `work-command`** in the receptor config YAML — the public key must be loaded before the work command references it.
3. **`requiretls` is invalid** in receptor 1.6.3 — use `requireclientcert: true` instead.
4. **Install bundle uses `ansible_host` as node ID** — when running via `virtctl port-forward` (`127.0.0.1`), the TLS cert CN won't match. The config must be corrected post-install.
5. **Cluster entitlement certs** from `etc-pki-entitlement` secret in `openshift-config-managed` allow the VM to access RHEL and AAP repos without `subscription-manager`.
6. **ClusterIP Service** is required so the controller pod can reach the VM's receptor on port 27199 via `aap-exec-node.aap-exec.svc.cluster.local`.

### 16.16 GitOps Files

```
gitops/apps/aap-exec-node/
├── kustomization.yaml          # Kustomize resources
├── namespace.yaml              # aap-exec namespace
├── virtualmachine.yaml         # RHEL 9 VM definition
├── service.yaml                # Receptor + SSH services
├── receptor-config.yaml        # Reference receptor.conf
├── receptor-systemd.service    # Reference systemd unit
└── configure-exec-node.sh      # Post-install configuration script
```

### 16.17 Ansible Playbook

```
ansible/playbooks/configure-exec-node.yml   # Phase 7: Full automated deployment
```

### 16.18 VM Access

```bash
# SSH into the VM
virtctl ssh -n aap-exec -i /tmp/aap-exec-node-key -l cloud-user vm/aap-exec-node

# Check receptor status
sudo systemctl status receptor
sudo receptorctl --socket /var/run/receptor/receptor.sock status
```

---

## Troubleshooting

### T1. Self-Service Portal Login: `Mismatching redirect URI`

**Symptom:** Clicking "Log in" on the Self-Service Automation Portal returns `Error: invalid_request Mismatching redirect URI`.

**Root Cause:** The AAP OAuth Application was configured with redirect URI `https://rhaap-portal-aap-portal.apps.ocp.karaoren.eu/oauth2/callback`, but the Backstage-based portal uses `/api/auth/rhaap/handler/frame` as its OAuth callback path.

**Fix:** Update the AAP OAuth Application redirect URI to match the portal's expected callback:

```bash
AAP_PW=$(oc get secret aap-admin-password -n aap -o jsonpath='{.data.password}' | base64 -d)
AAP_GW=$(oc get route aap -n aap -o jsonpath='{.spec.host}')

# Update the redirect URI for the Self-Service Automation Portal OAuth application (ID 1)
curl -sk -X PATCH "https://${AAP_GW}/api/gateway/v1/applications/1/" \
  -u "admin:${AAP_PW}" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": "https://rhaap-portal-aap-portal.apps.ocp.karaoren.eu/api/auth/rhaap/handler/frame"}'
```

| Setting | Wrong Value | Correct Value |
|---|---|---|
| Redirect URI | `/oauth2/callback` | `/api/auth/rhaap/handler/frame` |

> **Note:** The Backstage `@backstage/plugin-auth-backend-module-rhaap` plugin uses the `/api/auth/rhaap/handler/frame` callback path, not the generic `/oauth2/callback`.

---

## 17. Node System Tuning (Kubelet Reserved Resources)

### 17.1 Problem

On a Single-Node OpenShift cluster running many workloads (AAP, Vault, OpenShift Virtualization, ArgoCD, ESO, monitoring, etc.), the default `system-reserved` memory (~1.2 GiB) is insufficient. This triggers the alert:

> *System memory usage of X on hercules.ocp.karaoren.eu exceeds 95% of the reservation.*

If system processes (kubelet, CRI-O, kernel) are starved of memory, the node can become unstable or evict pods unexpectedly.

### 17.2 Solution

A `KubeletConfig` CR increases the `system-reserved` memory to **2 GiB**, giving system daemons sufficient headroom.

### 17.3 KubeletConfig CR

```yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: KubeletConfig
metadata:
  name: increase-system-reserved
spec:
  machineConfigPoolSelector:
    matchLabels:
      pools.operator.machineconfiguration.openshift.io/master: ""
  kubeletConfig:
    systemReserved:
      memory: "2Gi"
      cpu: "500m"
      ephemeral-storage: "1Gi"
```

The `master` pool label is used because on SNO the single node carries the `master` role.

### 17.4 Deployment

Managed via ArgoCD:

| Component | Path |
|-----------|------|
| **Manifest** | `gitops/cluster/system-tuning/kubelet-system-reserved.yaml` |
| **Kustomization** | `gitops/cluster/system-tuning/kustomization.yaml` |
| **ArgoCD Application** | `gitops/argocd/applications/12-system-tuning.yaml` |

### 17.5 Important Notes

- Applying or changing a `KubeletConfig` triggers a **MachineConfig rollout**, which **reboots the node**. On SNO this means **cluster downtime** — plan accordingly.
- After the rollout, verify the new allocatable memory:

```bash
# Monitor rollout
oc get mcp master -w

# Verify allocatable memory decreased (more is reserved for system)
oc get node hercules.ocp.karaoren.eu -o jsonpath='{.status.allocatable.memory}'

# Confirm the kubelet config was applied
oc debug node/hercules.ocp.karaoren.eu -- chroot /host cat /etc/kubernetes/kubelet.conf | grep -A5 systemReserved
```

### 17.6 Reserved Resources Summary

| Resource | Default | New Value |
|----------|---------|-----------|
| **Memory** | ~1.2 GiB | 2 GiB |
| **CPU** | 0 | 500m |
| **Ephemeral Storage** | 0 | 1 GiB |

> **Tip:** If the alert returns after increasing to 2 GiB, further increase to 2.5 or 3 GiB. Monitor actual system usage with: `oc adm top node`.
