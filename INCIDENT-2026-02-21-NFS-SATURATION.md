# Incident Report: NodeSystemSaturation -- NFS Server Hang

**Cluster:** ocp.karaoren.eu (Single-Node OpenShift)  
**Node:** hercules.ocp.karaoren.eu  
**Version:** OCP 4.20.14, RHCOS 9.6, kernel 5.14.0-570.86.1.el9_6.x86_64  
**Date:** February 21, 2026  
**Duration:** ~3 days (Feb 18 -- Feb 21)  
**Severity:** Critical  

---

## Table of Contents

1. [Alert](#1-alert)
2. [Investigation](#2-investigation)
3. [Root Cause](#3-root-cause)
4. [Resolution](#4-resolution)
5. [Prevention & Recommendations](#5-prevention--recommendations)

---

## 1. Alert

### Alert Details

| Field | Value |
|-------|-------|
| Alert | `NodeSystemSaturation` |
| Fired | February 21, 2026, 09:29 |
| Threshold | System load per core > 2 for 15 minutes |
| Observed value | **95.76** load per core (load average ~1,157 on 12 cores) |
| Node | hercules.ocp.karaoren.eu |

### Initial Observations

- CPU usage was only **13%** (1586m / 12 cores)
- Memory usage was only **14%** (35,975Mi / 256Gi)
- No memory pressure, disk pressure, or PID pressure conditions on the node
- Node was `Ready` and API server was responsive

The massive discrepancy between load average (~1,157) and actual CPU usage (13%) pointed to **I/O-related blocking**, not CPU saturation.

---

## 2. Investigation

### 2.1 Process State Analysis

```bash
# Thread state breakdown (ps -eLo state)
   4449 S   # Sleeping (normal)
   1157 D   # Uninterruptible sleep (PROBLEM)
    209 I   # Idle kernel threads
      5 R   # Running
```

**1,157 threads in D state** (uninterruptible I/O sleep) -- matching the load average exactly. On Linux, D-state threads count toward the load average because the kernel considers them "active" even though they are blocked on I/O.

### 2.2 Identifying the Stuck Threads

```bash
# D-state threads by process name
   1167 nfsplugin
      2 pulpcore-worker
      1 df
      1 crio
      1 172.30.139.236-
```

The **NFS CSI driver plugin (`nfsplugin`)** accounted for 1,167 of the stuck threads. The kernel thread `172.30.139.236-` is the NFS client connection to the NFS service ClusterIP.

### 2.3 NFS Mount Configuration

```
nfs-server.nfs-server.svc.cluster.local:/aap-aap-hub-file-storage
  type nfs4 (rw,relatime,vers=4.1,rsize=1048576,wsize=1048576,namlen=255,
  hard,proto=tcp,timeo=600,retrans=2,sec=sys,
  clientaddr=10.128.0.19,local_lock=none,addr=172.30.139.236)
```

The mount used the **`hard`** option, which causes NFS operations to block indefinitely until the server responds. There is no timeout -- threads will wait forever.

### 2.4 NFS Server Status

| Check | Result |
|-------|--------|
| Pod status | Running (1/1 Ready) |
| CPU usage | 1m |
| Memory usage | 161Mi |
| Backing PVC | 100Gi, 16% used (85Gi free) |
| `df -h` on NFS mount | **Timed out** (hung) |

The NFS server pod appeared healthy at the container level, but the NFS protocol layer was unresponsive. The `df -h | grep nfs` command timed out, confirming the mount was hung.

### 2.5 Affected AAP Pods

| Pod | Status | Details |
|-----|--------|---------|
| `aap-hub-web` | CrashLoopBackOff | 825 restarts over 3 days |
| `aap-hub-api` | CreateContainerError | Could not mount NFS volume |
| `aap-hub-content` (x2) | Running | Were running before the hang |
| `aap-hub-worker` (x2) | Running | `pulpcore-worker` threads stuck in D state |

### 2.6 Event Log Evidence

```
aap   Warning  BackOff    pod/aap-hub-web-6bc6f969bc-sv62b
  Back-off restarting failed container web

aap   Warning  Unhealthy  pod/aap-hub-web-6bc6f969bc-sv62b
  Liveness probe failed: HTTP probe failed with statuscode: 503

aap   Normal   Killing    pod/aap-hub-web-6bc6f969bc-sv62b
  Container web failed liveness probe, will be restarted

aap   Warning  Failed     pod/aap-hub-api-596969d84-qq7pz
  Error: context deadline exceeded
```

---

## 3. Root Cause

### Failure Chain

```
NFS server pod becomes unresponsive at NFS protocol level
    |
    v
NFS mounts on the node hang (hard mount = infinite wait)
    |
    v
AAP Hub pods can't start (need NFS volume for file-storage)
    |
    v
aap-hub-web enters CrashLoopBackOff (825 restarts)
    |
    v
Each restart attempt spawns new nfsplugin threads that immediately block
    |
    v
1,167 threads accumulate in D state over 3 days
    |
    v
Load average reaches ~1,157 (96 per core), triggering NodeSystemSaturation
```

### Why the NFS Server Hung

The NFS server uses the `registry.k8s.io/volume-nfs:0.8` image, a minimal NFS server container. While the container and its health checks remained "healthy" (the pod showed `Ready`), the NFS daemon inside became unresponsive. The exact trigger is unclear but could be:

- Internal NFS daemon deadlock
- Exhaustion of NFS server threads handling requests from the CSI driver
- Interaction between the NFS server and LVMS backing storage

### Why the Load Was So High Despite Low CPU

Linux load average counts both **runnable** (R state) and **uninterruptible sleep** (D state) tasks. The 1,157 threads stuck waiting on NFS I/O were all counted as "load" even though they consumed zero CPU. This is a well-known behavior that makes load average misleading when NFS or disk I/O hangs occur.

---

## 4. Resolution

### Step 1: Restart NFS Server Pod

```bash
oc delete pod nfs-server-867887db96-xtmvg -n nfs-server
```

New pod `nfs-server-867887db96-sm9w9` started successfully. NFS service resumed.

### Step 2: Restart NFS CSI Driver

```bash
oc delete pod csi-nfs-node-dzspz -n kube-system
oc delete pod csi-nfs-controller-67b57c9557-trmng -n kube-system
```

This cleared the 1,167 stuck `nfsplugin` threads. New CSI driver pods started clean.

### Step 3: Restart Stuck AAP Hub Pods

```bash
oc delete pod aap-hub-web-6bc6f969bc-sv62b -n aap
oc delete pod aap-hub-api-596969d84-qq7pz -n aap

# Force delete the pod stuck in Terminating state
oc delete pod aap-hub-api-596969d84-qq7pz -n aap --force --grace-period=0
```

New pods `aap-hub-web-6bc6f969bc-42ssw` and `aap-hub-api-596969d84-pjhg2` started and reached Running 1/1.

### Recovery Timeline

| Time (CET) | Load (1m) | Load (5m) | Load (15m) | Action |
|-------------|-----------|-----------|------------|--------|
| 22:39 | 1,157 | 1,151 | 1,136 | Investigation started |
| 22:52 | -- | -- | -- | NFS server pod restarted |
| 22:54 | -- | -- | -- | NFS CSI driver pods restarted |
| 22:55 | -- | -- | -- | AAP Hub pods restarted |
| 23:00 | **8.87** | 302 | 745 | D-state threads cleared |
| 23:01 | **8.46** | 229 | 681 | Continued decay |

### Final State

```
All AAP pods: Running (no restarts on new pods)
NFS server: Running, NFS exports healthy
NFS CSI driver: Running, clean state
D-state threads: 6 (residual, down from 1,167)
Node conditions: Ready, no pressure conditions
```

---

## 5. Prevention & Recommendations

### 5.1 Add NFS-Level Health Check

The NFS server pod's readiness probe does not test actual NFS functionality. Add a probe that mounts and tests the NFS export:

```yaml
livenessProbe:
  exec:
    command:
      - /bin/sh
      - -c
      - "showmount -e localhost && stat /exports"
  initialDelaySeconds: 30
  periodSeconds: 30
  timeoutSeconds: 10
  failureThreshold: 3
```

### 5.2 Consider Soft NFS Mount

Switching from `hard` to `soft` mount with a timeout prevents indefinite thread blocking. This trades strict data consistency for availability:

```
mountOptions:
  - soft
  - timeo=30
  - retrans=3
```

With `soft`, failed NFS operations return errors instead of blocking forever, allowing pods to fail fast and CrashLoopBackOff without accumulating stuck threads.

### 5.3 Monitor NFS-Specific Metrics

Add a PrometheusRule to alert on NFS issues before they cascade:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: nfs-server-alerts
  namespace: nfs-server
spec:
  groups:
    - name: nfs-server
      rules:
        - alert: NfsServerPodRestart
          expr: increase(kube_pod_container_status_restarts_total{namespace="nfs-server"}[1h]) > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "NFS server pod has restarted"
        - alert: NfsCsiThreadsStuck
          expr: count(node_processes_state{state="D"}) > 50
          for: 10m
          labels:
            severity: critical
          annotations:
            summary: "High number of D-state processes, possible NFS hang"
```

### 5.4 Consider Replacing In-Cluster NFS

The `registry.k8s.io/volume-nfs:0.8` image is a minimal, community NFS server not designed for production workloads. Alternatives:

- **OpenShift Data Foundation (ODF)** for production-grade RWX storage
- **A dedicated NFS server VM** outside the cluster with proper monitoring
- **S3-based storage** for AAP Hub content (Pulp supports S3 backends)
