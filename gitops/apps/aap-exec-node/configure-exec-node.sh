#!/bin/bash
# =============================================================================
# AAP Execution Node Configuration Script
# =============================================================================
# This script configures a RHEL 9 VM on OpenShift Virtualization as an
# AAP 2.6 execution node. It must be run AFTER the VM is up and the
# execution node has been registered in AAP (to obtain the install bundle).
#
# Prerequisites:
#   - VM is running and accessible via virtctl ssh
#   - oc CLI is logged in
#   - virtctl is available at /tmp/virtctl (or in PATH)
#   - SSH key generated for VM access
#
# Usage:
#   ./configure-exec-node.sh
# =============================================================================

set -euo pipefail

# --- Configuration ---
VM_NAME="aap-exec-node"
VM_NAMESPACE="aap-exec"
SSH_KEY="/tmp/aap-exec-node-key"
VIRTCTL="${VIRTCTL_PATH:-/tmp/virtctl}"
AAP_NAMESPACE="aap"

# --- Functions ---
log() { echo "=== $(date '+%H:%M:%S') $1 ==="; }

virtctl_ssh() {
  $VIRTCTL ssh -n "$VM_NAMESPACE" \
    -i "$SSH_KEY" \
    -l cloud-user \
    -t "-o StrictHostKeyChecking=no" \
    -t "-o UserKnownHostsFile=/dev/null" \
    -c "$1" \
    "vm/${VM_NAME}" 2>&1
}

# --- Step 0: Generate SSH key if needed ---
if [ ! -f "$SSH_KEY" ]; then
  log "Generating SSH key"
  ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "aap-exec-node"
fi

# --- Step 1: Wait for VM to be running ---
log "Waiting for VM to be running"
for i in $(seq 1 30); do
  STATUS=$(oc get vm "$VM_NAME" -n "$VM_NAMESPACE" -o jsonpath='{.status.printableStatus}' 2>/dev/null || echo "NotFound")
  echo "  [$i] VM status: $STATUS"
  [ "$STATUS" = "Running" ] && break
  sleep 15
done

# --- Step 2: Extract cluster entitlement certificates ---
log "Extracting entitlement certificates"
mkdir -p /tmp/entitlement
oc get secret etc-pki-entitlement -n openshift-config-managed -o jsonpath='{.data}' | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for k, v in data.items():
    with open(f'/tmp/entitlement/{k}', 'wb') as f:
        f.write(base64.b64decode(v))
    print(f'  Wrote: /tmp/entitlement/{k}')
"

# --- Step 3: Copy entitlement certs to VM ---
log "Copying entitlement certificates to VM"
for f in /tmp/entitlement/*; do
  $VIRTCTL scp -n "$VM_NAMESPACE" \
    -i "$SSH_KEY" -l cloud-user \
    -t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null" \
    "$f" "vm/${VM_NAME}:/home/cloud-user/$(basename $f)"
done

# --- Step 4: Install entitlement certs and enable repos on VM ---
log "Configuring RHEL repos on VM"
virtctl_ssh '
set -e
sudo mkdir -p /etc/pki/entitlement
sudo cp /home/cloud-user/entitlement*.pem /etc/pki/entitlement/

sudo tee /etc/yum.repos.d/rhel9.repo > /dev/null << REPOEOF
[rhel-9-baseos]
name=Red Hat Enterprise Linux 9 - BaseOS
baseurl=https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
sslclientcert=/etc/pki/entitlement/entitlement.pem
sslclientkey=/etc/pki/entitlement/entitlement-key.pem
sslcacert=/etc/rhsm/ca/redhat-uep.pem
sslverify=1

[rhel-9-appstream]
name=Red Hat Enterprise Linux 9 - AppStream
baseurl=https://cdn.redhat.com/content/dist/rhel9/9/x86_64/appstream/os
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
sslclientcert=/etc/pki/entitlement/entitlement.pem
sslclientkey=/etc/pki/entitlement/entitlement-key.pem
sslcacert=/etc/rhsm/ca/redhat-uep.pem
sslverify=1
REPOEOF

sudo tee /etc/yum.repos.d/aap-2.6.repo > /dev/null << REPOEOF
[ansible-automation-platform-2.6-for-rhel-9-x86_64-rpms]
name=Red Hat Ansible Automation Platform 2.6 for RHEL 9 x86_64
baseurl=https://cdn.redhat.com/content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.6/os
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
sslclientcert=/etc/pki/entitlement/entitlement.pem
sslclientkey=/etc/pki/entitlement/entitlement-key.pem
sslcacert=/etc/rhsm/ca/redhat-uep.pem
sslverify=1
REPOEOF

echo "✅ Repos configured"
sudo dnf repolist
'

# --- Step 5: Install packages ---
log "Installing receptor, ansible-runner, podman"
virtctl_ssh '
set -e
sudo dnf install -y receptor ansible-runner podman python3 python3-pip 2>&1 | tail -5
echo ""
echo "receptor: $(receptor --version 2>/dev/null)"
echo "ansible-runner: $(ansible-runner --version 2>/dev/null)"
echo "podman: $(podman --version 2>/dev/null)"
'

# --- Step 6: Register execution node in AAP and download install bundle ---
log "Registering execution node in AAP"
AAP_GW=$(oc get route aap -n "$AAP_NAMESPACE" -o jsonpath='{.spec.host}')
AAP_PW=$(oc get secret aap-admin-password -n "$AAP_NAMESPACE" -o jsonpath='{.data.password}' | base64 -d)
EXEC_HOSTNAME="${VM_NAME}.${VM_NAMESPACE}.svc.cluster.local"

# Create the instance
INSTANCE_ID=$(curl -sk -u "admin:${AAP_PW}" \
  -X POST -H "Content-Type: application/json" \
  "https://${AAP_GW}/api/controller/v2/instances/" \
  -d "{
    \"hostname\": \"${EXEC_HOSTNAME}\",
    \"node_type\": \"execution\",
    \"listener_port\": 27199,
    \"peers_from_control_nodes\": true
  }" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")

echo "  Instance ID: $INSTANCE_ID"

# Download install bundle
log "Downloading install bundle"
curl -sk -u "admin:${AAP_PW}" \
  "https://${AAP_GW}/api/controller/v2/instances/${INSTANCE_ID}/install_bundle/" \
  -o /tmp/aap-exec-bundle.tar.gz

# --- Step 7: Copy bundle to VM ---
log "Copying install bundle to VM"
$VIRTCTL scp -n "$VM_NAMESPACE" \
  -i "$SSH_KEY" -l cloud-user \
  -t "-o StrictHostKeyChecking=no" -t "-o UserKnownHostsFile=/dev/null" \
  /tmp/aap-exec-bundle.tar.gz "vm/${VM_NAME}:/home/cloud-user/aap-exec-bundle.tar.gz"

# --- Step 8: Install receptor TLS certs and configure ---
log "Installing receptor TLS certificates and configuration"
virtctl_ssh "
set -e
cd /home/cloud-user
tar xzf aap-exec-bundle.tar.gz
BDIR=\$(ls -d *_install_bundle)

# Create awx user
sudo useradd -r -s /bin/bash awx 2>/dev/null || true

# Install TLS certs
sudo mkdir -p /etc/receptor/tls/ca
sudo cp \$BDIR/receptor/tls/ca/mesh-CA.crt /etc/receptor/tls/ca/
sudo cp \$BDIR/receptor/tls/receptor.crt /etc/receptor/tls/
sudo cp \$BDIR/receptor/tls/receptor.key /etc/receptor/tls/
sudo cp \$BDIR/receptor/work_public_key.pem /etc/receptor/
sudo chown -R awx:awx /etc/receptor
sudo chmod 0600 /etc/receptor/tls/receptor.key

# Write receptor.conf
sudo tee /etc/receptor/receptor.conf > /dev/null << 'RCEOF'
---
- node:
    id: ${EXEC_HOSTNAME}

- work-verification:
    publickey: /etc/receptor/work_public_key.pem

- log-level: info

- control-service:
    service: control
    filename: /var/run/receptor/receptor.sock
    permissions: \"0660\"

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
RCEOF

sudo chown awx:awx /etc/receptor/receptor.conf

# Create directories
sudo mkdir -p /var/run/receptor /var/lib/receptor
sudo chown awx:awx /var/run/receptor /var/lib/receptor

# Enable podman linger for awx
sudo loginctl enable-linger awx

# Start receptor
sudo systemctl daemon-reload
sudo systemctl enable receptor
sudo systemctl restart receptor
sleep 2
sudo systemctl status receptor --no-pager | head -10
echo ''
ss -tlnp | grep 27199
echo '✅ Receptor configured and running'
"

# --- Step 9: Add execution node to default instance group ---
log "Adding execution node to default instance group"
curl -sk -u "admin:${AAP_PW}" \
  -X POST -H "Content-Type: application/json" \
  "https://${AAP_GW}/api/controller/v2/instance_groups/2/instances/" \
  -d "{\"id\": ${INSTANCE_ID}}" -w "HTTP %{http_code}\n" 2>/dev/null

# --- Step 10: Trigger health check ---
log "Triggering health check"
curl -sk -u "admin:${AAP_PW}" \
  -X POST -H "Content-Type: application/json" \
  "https://${AAP_GW}/api/controller/v2/instances/${INSTANCE_ID}/health_check/" 2>/dev/null | python3 -m json.tool

sleep 15

# --- Step 11: Verify ---
log "Verifying execution node"
curl -sk -u "admin:${AAP_PW}" \
  "https://${AAP_GW}/api/controller/v2/instances/${INSTANCE_ID}/" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
for k in ['hostname','node_type','node_state','capacity','cpu','memory','version','enabled']:
    print(f'  {k}: {d.get(k)}')
"

log "Done! Execution node is configured."

# Cleanup
rm -f /tmp/aap-exec-bundle.tar.gz
rm -rf /tmp/entitlement
