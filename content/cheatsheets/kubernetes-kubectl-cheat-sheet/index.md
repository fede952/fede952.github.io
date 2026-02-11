---
title: "Kubernetes (K8s) & Kubectl: Production Cluster Commands"
description: "Essential kubectl commands for managing Kubernetes clusters in production. Covers pod management, deployments, services, ConfigMaps, secrets, and cluster debugging techniques."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl cheat sheet", "k8s commands", "pod management kubernetes", "deployment scaling k8s", "kubernetes debugging", "kubectl get pods", "kubernetes service expose", "configmap secrets k8s", "kubernetes cluster admin", "kubectl logs troubleshoot"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: Production Cluster Commands",
    "description": "Essential kubectl commands for managing Kubernetes clusters: pods, deployments, services, ConfigMaps, and debugging.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## System Init

Kubernetes is the operating system for the cloud. It orchestrates containers across clusters of machines, handling scaling, self-healing, load balancing, and service discovery automatically. But all that power is accessed through a single command-line tool: `kubectl`. This field manual contains the kubectl commands you need for every phase of cluster management — from deploying your first pod to debugging production incidents at 3 AM. Every command is production-tested and organized by workflow, so you can find what you need in seconds.

All commands assume you have a valid kubeconfig and cluster access. Verify with `kubectl cluster-info`.

---

## Cluster Context

Before running any command, you need to know which cluster and namespace you are targeting. Kubernetes supports multiple contexts, allowing you to switch between development, staging, and production clusters from the same terminal. Getting this wrong can mean deploying test code to production, so always verify your context first.

### Context management

```bash
# View current context
kubectl config current-context

# List all available contexts
kubectl config get-contexts

# Switch to a different context
kubectl config use-context production-cluster

# Set default namespace for current context
kubectl config set-context --current --namespace=my-namespace

# View the full kubeconfig
kubectl config view
```

### Cluster information

```bash
# Display cluster endpoint and services
kubectl cluster-info

# List all nodes in the cluster
kubectl get nodes

# Show detailed node information
kubectl describe node <node-name>

# View cluster resource usage
kubectl top nodes

# Check API server version
kubectl version
```

---

## Pods

Pods are the smallest deployable unit in Kubernetes — a group of one or more containers that share storage and network resources. In practice, most pods contain a single container, but sidecar patterns (logging agents, proxies) use multi-container pods. Understanding pod management is fundamental because every workload in Kubernetes ultimately runs as a pod.

### List and inspect pods

```bash
# List pods in the current namespace
kubectl get pods

# List pods in all namespaces
kubectl get pods -A

# List pods with additional details (IP, node, status)
kubectl get pods -o wide

# Watch pods in real-time
kubectl get pods -w

# Describe a pod (events, conditions, container status)
kubectl describe pod <pod-name>

# Get pod YAML definition
kubectl get pod <pod-name> -o yaml
```

### Create and manage pods

```bash
# Run a pod from an image (quick test)
kubectl run debug-pod --image=busybox --restart=Never -- sleep 3600

# Run an interactive pod with a shell
kubectl run -it debug --image=busybox --restart=Never -- /bin/sh

# Delete a pod
kubectl delete pod <pod-name>

# Delete a pod forcefully (skip graceful shutdown)
kubectl delete pod <pod-name> --grace-period=0 --force

# Apply a pod definition from YAML
kubectl apply -f pod.yaml
```

### Pod logs and debugging

```bash
# View pod logs
kubectl logs <pod-name>

# Follow logs in real-time
kubectl logs -f <pod-name>

# View logs from a specific container in a multi-container pod
kubectl logs <pod-name> -c <container-name>

# View logs from a previous instance (after crash)
kubectl logs <pod-name> --previous

# Execute a command in a running pod
kubectl exec -it <pod-name> -- /bin/bash

# Copy files to/from a pod
kubectl cp <pod-name>:/path/to/file ./local-file
kubectl cp ./local-file <pod-name>:/path/to/file

# Port forward to access a pod locally
kubectl port-forward <pod-name> 8080:80
```

---

## Deployments

Deployments are the standard way to run stateless applications in Kubernetes. They manage ReplicaSets, which in turn manage pods — giving you declarative updates, rolling deployments, and automatic rollbacks. When you update a deployment's image or configuration, Kubernetes gradually replaces old pods with new ones, ensuring zero-downtime deployments. This is the resource you will use most in production.

### Manage deployments

```bash
# List all deployments
kubectl get deployments

# Create a deployment from an image
kubectl create deployment my-app --image=myapp:latest --replicas=3

# Apply a deployment from YAML
kubectl apply -f deployment.yaml

# View deployment details
kubectl describe deployment my-app

# View rollout status
kubectl rollout status deployment/my-app

# View rollout history
kubectl rollout history deployment/my-app
```

### Scaling

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Updates and rollbacks

```bash
# Update a deployment's image (triggers rolling update)
kubectl set image deployment/my-app my-app=myapp:v2

# Rollback to the previous version
kubectl rollout undo deployment/my-app

# Rollback to a specific revision
kubectl rollout undo deployment/my-app --to-revision=3

# Pause a rollout (for canary testing)
kubectl rollout pause deployment/my-app

# Resume a paused rollout
kubectl rollout resume deployment/my-app
```

---

## Services

Services provide stable network endpoints for your pods. Since pods are ephemeral and get new IP addresses when recreated, you cannot rely on pod IPs for communication. A Service creates a persistent virtual IP and DNS name that routes traffic to the correct pods, regardless of how many replicas exist or where they are scheduled. This is how services discover and communicate with each other inside a Kubernetes cluster.

### Create and manage services

```bash
# Expose a deployment as a ClusterIP service (internal only)
kubectl expose deployment my-app --port=80 --target-port=3000

# Expose as a NodePort service (accessible from outside the cluster)
kubectl expose deployment my-app --type=NodePort --port=80 --target-port=3000

# Expose as a LoadBalancer service (cloud provider creates an external LB)
kubectl expose deployment my-app --type=LoadBalancer --port=80 --target-port=3000

# List all services
kubectl get services

# Describe a service
kubectl describe service my-app

# Delete a service
kubectl delete service my-app
```

### DNS and service discovery

```bash
# Services are accessible via DNS: <service-name>.<namespace>.svc.cluster.local
# From a pod in the same namespace:
curl http://my-app:80

# From a pod in a different namespace:
curl http://my-app.production.svc.cluster.local:80

# Test DNS resolution from inside a pod
kubectl exec -it debug-pod -- nslookup my-app
```

---

## ConfigMaps and Secrets

ConfigMaps store non-sensitive configuration data (environment variables, config files), while Secrets store sensitive data (passwords, API keys, TLS certificates). Both decouple configuration from container images, allowing you to change settings without rebuilding or redeploying your application. In production, Secrets should always be encrypted at rest and access-controlled via RBAC.

### ConfigMaps

```bash
# Create a ConfigMap from literal values
kubectl create configmap app-config --from-literal=DB_HOST=postgres --from-literal=DB_PORT=5432

# Create a ConfigMap from a file
kubectl create configmap app-config --from-file=config.yaml

# List ConfigMaps
kubectl get configmaps

# View ConfigMap data
kubectl describe configmap app-config

# Delete a ConfigMap
kubectl delete configmap app-config
```

### Secrets

```bash
# Create a Secret from literal values
kubectl create secret generic db-creds --from-literal=username=admin --from-literal=password=secret

# Create a TLS Secret
kubectl create secret tls my-tls --cert=tls.crt --key=tls.key

# List Secrets
kubectl get secrets

# View Secret data (base64 encoded)
kubectl get secret db-creds -o yaml

# Decode a Secret value
kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d
```

---

## Debugging Clusters

Production debugging in Kubernetes requires knowing where to look. Pods crashing? Check events and logs. Service unreachable? Check endpoints and network policies. Node unresponsive? Check node conditions and resource pressure. This section contains the commands that have saved countless on-call engineers during production incidents.

### Diagnostic commands

```bash
# View cluster events (sorted by time)
kubectl get events --sort-by=.metadata.creationTimestamp

# View events for a specific namespace
kubectl get events -n production

# Check pod resource usage
kubectl top pods

# Check node resource usage
kubectl top nodes

# View pod conditions and restart counts
kubectl get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount

# Check endpoints for a service (are pods actually behind it?)
kubectl get endpoints my-app
```

### Debugging pods

```bash
# Describe a pod to see events, conditions, and state transitions
kubectl describe pod <pod-name>

# Check why a pod is in CrashLoopBackOff
kubectl logs <pod-name> --previous

# Run a debug container attached to a failing pod (Kubernetes 1.25+)
kubectl debug -it <pod-name> --image=busybox --target=<container-name>

# Create a copy of a pod with a debug container
kubectl debug <pod-name> -it --copy-to=debug-pod --container=debug --image=ubuntu

# Check pod resource requests and limits
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].resources}'
```

### Namespace management

```bash
# List all namespaces
kubectl get namespaces

# Create a namespace
kubectl create namespace staging

# Delete a namespace (and all resources within it)
kubectl delete namespace staging

# Get all resources in a namespace
kubectl get all -n production
```
