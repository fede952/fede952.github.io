---
title: "Kubernetes (K8s) Interview Prep: Senior Level Q&A"
description: "20 advanced Kubernetes interview questions for Senior DevOps and SRE roles. Covers architecture, pod lifecycle, networking, storage, RBAC, and production troubleshooting."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) Interview Prep: Senior Level Q&A",
    "description": "20 advanced Kubernetes interview questions covering architecture, networking, storage, security, and production troubleshooting.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "en"
  }
---

## System Init

Kubernetes is the operating system of the cloud — and the most in-demand skill for DevOps, SRE, and Platform Engineering roles. Senior-level interviews go deep: you will be asked about control plane internals, networking models, RBAC, resource management, and how to debug production incidents under pressure. This guide contains 20 questions that repeatedly appear in interviews at top tech companies, with answers that demonstrate the depth expected at Staff/Senior level.

**Need a quick command refresher?** Keep our [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) open during your prep.

---

## Architecture

<details>
<summary><strong>1. Describe the Kubernetes control plane components and their responsibilities.</strong></summary>
<br>

The control plane manages the cluster state:

- **kube-apiserver**: The front door to the cluster. Every `kubectl` command, controller action, and scheduler decision goes through the API server. It validates and persists state to etcd.
- **etcd**: A distributed key-value store that holds the entire cluster state (desired state, actual state, configs, secrets). It is the single source of truth.
- **kube-scheduler**: Watches for newly created pods with no assigned node and selects a node based on resource requirements, affinity rules, taints, and constraints.
- **kube-controller-manager**: Runs controller loops (Deployment, ReplicaSet, Node, Job controllers) that continuously reconcile desired state with actual state.
- **cloud-controller-manager**: Integrates with cloud provider APIs for LoadBalancers, storage provisioning, and node lifecycle.
</details>

<details>
<summary><strong>2. What happens when you run `kubectl apply -f deployment.yaml`?</strong></summary>
<br>

1. `kubectl` sends an HTTP POST/PATCH to the **API server** with the Deployment manifest.
2. The API server **validates** the request (authentication, authorization via RBAC, admission controllers).
3. The API server writes the Deployment object to **etcd**.
4. The **Deployment controller** detects the new Deployment and creates a **ReplicaSet**.
5. The **ReplicaSet controller** detects it and creates the specified number of **Pod** objects.
6. The **scheduler** detects unscheduled pods and assigns each to a node based on resource availability and constraints.
7. The **kubelet** on each assigned node detects the pod assignment, pulls the container image, and starts the container via the container runtime (containerd/CRI-O).
8. The **kube-proxy** on each node updates iptables/IPVS rules if a Service is associated.
</details>

<details>
<summary><strong>3. What is the difference between a Deployment, StatefulSet, and DaemonSet?</strong></summary>
<br>

- **Deployment**: Manages stateless applications. Pods are interchangeable, can be scaled freely, and are created/destroyed in any order. Best for web servers, APIs, workers.
- **StatefulSet**: Manages stateful applications. Each pod gets a **stable hostname** (`pod-0`, `pod-1`), **persistent storage** (PVC per pod), and pods are created/destroyed in **order**. Best for databases, Kafka, ZooKeeper.
- **DaemonSet**: Ensures **one pod per node**. When a new node joins the cluster, a pod is automatically scheduled on it. Best for log collectors, monitoring agents, network plugins.
</details>

<details>
<summary><strong>4. Explain the pod lifecycle and its phases.</strong></summary>
<br>

A pod goes through these phases:

1. **Pending**: The pod is accepted but not yet scheduled or images are being pulled.
2. **Running**: At least one container is running or starting/restarting.
3. **Succeeded**: All containers exited with code 0 (for Jobs/batch workloads).
4. **Failed**: All containers terminated, at least one exited with a non-zero code.
5. **Unknown**: The node is unreachable, pod state cannot be determined.

Within a running pod, containers can be in states: **Waiting** (pulling image, init containers), **Running**, or **Terminated** (exited or crashed).
</details>

## Networking

<details>
<summary><strong>5. Explain the Kubernetes networking model.</strong></summary>
<br>

Kubernetes networking follows three fundamental rules:

1. **Every pod gets its own IP address** — no NAT between pods.
2. **All pods can communicate with all other pods** across nodes without NAT.
3. **The IP a pod sees itself as** is the same IP others use to reach it.

This is implemented by CNI (Container Network Interface) plugins like Calico, Flannel, Cilium, or Weave. They create an overlay or underlay network that satisfies these rules. Each node gets a pod CIDR subnet, and the CNI plugin handles routing between nodes.
</details>

<details>
<summary><strong>6. What is the difference between ClusterIP, NodePort, and LoadBalancer services?</strong></summary>
<br>

- **ClusterIP** (default): Internal-only virtual IP. Accessible only from within the cluster. Used for inter-service communication.
- **NodePort**: Exposes the service on a static port (30000-32767) on every node's IP. External traffic can reach `<NodeIP>:<NodePort>`. Builds on top of ClusterIP.
- **LoadBalancer**: Provisions an external load balancer via the cloud provider. Gets a public IP/DNS. Builds on top of NodePort. Used for production public-facing services.

There is also **ExternalName**, which maps a service to a DNS CNAME (no proxying, just DNS resolution).
</details>

<details>
<summary><strong>7. What is an Ingress and how does it differ from a Service?</strong></summary>
<br>

A **Service** operates at Layer 4 (TCP/UDP) — it routes traffic to pods based on IP and port.

An **Ingress** operates at Layer 7 (HTTP/HTTPS) — it routes traffic based on hostname and URL path. A single Ingress can route `api.example.com` to the API service and `app.example.com` to the frontend service, all through one load balancer.

An Ingress requires an **Ingress Controller** (nginx-ingress, Traefik, HAProxy, AWS ALB) to actually implement the routing rules. The Ingress resource is just a configuration — the controller does the work.
</details>

<details>
<summary><strong>8. How does DNS work inside a Kubernetes cluster?</strong></summary>
<br>

Kubernetes runs **CoreDNS** (or kube-dns) as a cluster add-on. Every service gets a DNS record:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

When a pod makes a DNS query for `my-service`, the resolver in `/etc/resolv.conf` (configured by kubelet) appends the search domains and queries CoreDNS. CoreDNS watches the API server for Service/Endpoint changes and updates its records automatically.
</details>

## Storage

<details>
<summary><strong>9. Explain PersistentVolume (PV), PersistentVolumeClaim (PVC), and StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)**: A piece of storage provisioned by an admin or dynamically by a StorageClass. It exists independently of any pod. Has a lifecycle separate from pods.
- **PersistentVolumeClaim (PVC)**: A request for storage by a pod. Specifies size, access mode, and optionally a StorageClass. Kubernetes binds the PVC to a matching PV.
- **StorageClass**: Defines a class of storage (SSD, HDD, NFS) and the provisioner that creates PVs dynamically. Enables on-demand storage provisioning — no admin intervention needed.

Flow: Pod references PVC → PVC requests storage from StorageClass → StorageClass triggers provisioner → Provisioner creates PV → PVC binds to PV → Pod mounts PV.
</details>

<details>
<summary><strong>10. What are access modes and reclaim policies?</strong></summary>
<br>

**Access Modes**:
- **ReadWriteOnce (RWO)**: Mounted read/write by a single node. Most common (AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)**: Mounted read-only by many nodes. Used for shared configs.
- **ReadWriteMany (RWX)**: Mounted read/write by many nodes. Requires network storage (NFS, EFS, CephFS).

**Reclaim Policies** (what happens when PVC is deleted):
- **Retain**: PV is kept with its data. Admin must manually reclaim it.
- **Delete**: PV and underlying storage are deleted. Default for dynamic provisioning.
- **Recycle** (deprecated): Basic `rm -rf` on the volume. Use Retain or Delete instead.
</details>

## Security & RBAC

<details>
<summary><strong>11. How does RBAC work in Kubernetes?</strong></summary>
<br>

RBAC (Role-Based Access Control) has four objects:

- **Role**: Defines permissions (verbs: get, list, create, delete) on resources (pods, services, secrets) within a **single namespace**.
- **ClusterRole**: Same as Role but **cluster-wide** (all namespaces, or cluster-scoped resources like nodes).
- **RoleBinding**: Binds a Role to a user, group, or service account within a namespace.
- **ClusterRoleBinding**: Binds a ClusterRole to a subject across the entire cluster.

Principle: Start with the minimum permissions needed. Never bind `cluster-admin` to application service accounts. Audit RBAC regularly with `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. What are Pod Security Standards (PSS)?</strong></summary>
<br>

Pod Security Standards replaced PodSecurityPolicies (removed in K8s 1.25). They define three security levels:

- **Privileged**: Unrestricted. Allows everything. Used for system-level pods (CNI plugins, storage drivers).
- **Baseline**: Prevents known privilege escalations. Blocks hostNetwork, hostPID, privileged containers, but allows most workloads.
- **Restricted**: Maximum security. Requires non-root, drop all capabilities, read-only root filesystem, no privilege escalation.

Enforced via the **Pod Security Admission** controller at the namespace level using labels:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. How do you manage secrets in Kubernetes securely?</strong></summary>
<br>

Default Kubernetes secrets are **base64 encoded, not encrypted**. Anyone with API access can decode them.

Hardening steps:
1. **Enable encryption at rest** in etcd (`EncryptionConfiguration` with AES-CBC or KMS provider).
2. **Use external secret managers** (Vault, AWS Secrets Manager) with the External Secrets Operator or CSI Secrets Store Driver.
3. **RBAC**: Restrict `get`/`list` on secrets to only the service accounts that need them.
4. **Mount as files**, not environment variables — env vars can leak via logs, crash dumps, and `/proc`.
5. **Rotate secrets** regularly and use short-lived credentials where possible.
</details>

## Scheduling & Resources

<details>
<summary><strong>14. Explain resource requests and limits.</strong></summary>
<br>

- **Requests**: The amount of CPU/memory **guaranteed** to the container. The scheduler uses requests to decide which node has enough capacity.
- **Limits**: The **maximum** amount a container can use. If a container exceeds its memory limit, it is OOM-killed. If it exceeds CPU limit, it is throttled.

QoS classes based on requests/limits:
- **Guaranteed**: Requests == Limits for all containers. Highest priority, last to be evicted.
- **Burstable**: Requests < Limits. Medium priority.
- **BestEffort**: No requests or limits set. First to be evicted under pressure.

Best practice: Always set requests (for scheduling accuracy) and limits (for cluster stability).
</details>

<details>
<summary><strong>15. What are taints, tolerations, and node affinity?</strong></summary>
<br>

- **Taints** are applied to nodes: "Don't schedule pods here unless they tolerate this taint." Example: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Tolerations** are applied to pods: "I can tolerate this taint." Pods with matching tolerations can be scheduled on tainted nodes.
- **Node Affinity** is a pod spec that says "Prefer or require scheduling on nodes with specific labels." Example: require nodes with `disktype=ssd`.

Use together: Taint GPU nodes → only pods with GPU tolerations and GPU affinity land there. Prevents non-GPU workloads from wasting expensive hardware.
</details>

## Troubleshooting

<details>
<summary><strong>16. A pod is stuck in CrashLoopBackOff. How do you debug it?</strong></summary>
<br>

`CrashLoopBackOff` means the container keeps crashing and Kubernetes is backing off before restarting it (exponential delay up to 5 minutes).

Debug steps:
1. `kubectl describe pod <name>` — check Events, Last State, Exit Code.
2. `kubectl logs <pod> --previous` — read logs from the crashed instance.
3. Exit code analysis: 1 = app error, 137 = OOM killed, 139 = segfault, 143 = SIGTERM.
4. If the container crashes too fast for logs: `kubectl run debug --image=<image> --command -- sleep 3600` and exec in to inspect the environment.
5. Check if readiness/liveness probes are misconfigured (probe hitting wrong port/path).
6. Check resource limits — the container may be OOM killed before it can log anything.
</details>

<details>
<summary><strong>17. A Service is not routing traffic to pods. What do you check?</strong></summary>
<br>

1. **Labels match**: The Service's `spec.selector` must match the pod's `metadata.labels` exactly.
2. **Endpoints exist**: `kubectl get endpoints <service>` — if empty, the selector doesn't match any running pods.
3. **Pods are Ready**: Only pods passing readiness probes appear in Endpoints. Check `kubectl get pods` for Ready status.
4. **Port mismatch**: The Service `targetPort` must match the port the container is actually listening on.
5. **Network Policy**: A NetworkPolicy might be blocking ingress to the pods.
6. **DNS**: From a debug pod, `nslookup <service-name>` to verify DNS resolution works.
</details>

<details>
<summary><strong>18. How do you perform a zero-downtime deployment?</strong></summary>
<br>

1. **Rolling update strategy** (default): Set `maxUnavailable: 0` and `maxSurge: 1` to ensure old pods are only removed after new pods are Ready.
2. **Readiness probes**: Without a readiness probe, Kubernetes considers a pod Ready immediately after start — traffic hits it before the app is initialized.
3. **PreStop hook**: Add a `preStop` lifecycle hook with a short sleep (5-10s) to allow in-flight requests to complete before the pod is removed from the Service endpoints.
4. **PodDisruptionBudget (PDB)**: Ensures a minimum number of pods are always available during voluntary disruptions (node drains, upgrades).
5. **Graceful shutdown**: The application must handle SIGTERM and finish active requests before exiting.
</details>

<details>
<summary><strong>19. What is a Horizontal Pod Autoscaler and how does it work?</strong></summary>
<br>

HPA automatically scales the number of pod replicas based on observed metrics (CPU, memory, or custom metrics).

How it works:
1. HPA queries the **Metrics Server** (or custom metrics API) every 15 seconds.
2. It calculates: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. If desired replicas differ from current, it updates the Deployment's replica count.
4. Cooldown periods prevent thrashing: scale-up stabilization (0s default), scale-down stabilization (300s default).

Requirements: Metrics Server installed, resource requests defined on containers (for CPU/memory metrics), min/max replica bounds configured.
</details>

<details>
<summary><strong>20. What is the difference between a liveness probe and a readiness probe?</strong></summary>
<br>

- **Liveness probe**: "Is the container alive?" If it fails, kubelet **kills and restarts** the container. Use for detecting deadlocks or frozen processes.
- **Readiness probe**: "Is the container ready to serve traffic?" If it fails, the pod is **removed from Service endpoints** (no traffic routed to it), but the container is NOT restarted. Use for warm-up periods, dependency checks, temporary overload.

There is also a **Startup probe**: Disables liveness/readiness probes until the app has started. Useful for slow-starting applications to prevent premature kills.

Common mistake: Using a liveness probe that checks a downstream dependency (database). If the database goes down, all pods restart — making the outage worse. Liveness should only check the application itself.
</details>
