---
title: "Kubernetes (K8s) & Kubectl：生产集群命令大全"
description: "管理生产环境Kubernetes集群的必备kubectl命令。涵盖Pod管理、Deployment、Service、ConfigMap、Secret以及集群调试技术。"
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl 速查表", "k8s 命令", "Pod管理 kubernetes", "Deployment扩展 k8s", "kubernetes 调试", "kubectl get pods", "kubernetes 服务暴露", "configmap secrets k8s", "kubernetes 集群管理", "kubectl logs 故障排除"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl：生产集群命令大全",
    "description": "管理Kubernetes集群的必备kubectl命令：Pod、Deployment、Service、ConfigMap和调试。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

Kubernetes是云的操作系统。它跨机器集群编排容器，自动处理扩展、自愈、负载均衡和服务发现。但所有这些强大功能都通过一个命令行工具来访问：`kubectl`。本实战手册包含了集群管理各个阶段所需的kubectl命令——从部署第一个Pod到凌晨3点调试生产故障。每个命令都经过生产环境测试，并按工作流程组织，让你在几秒内找到所需内容。

所有命令假设你拥有有效的kubeconfig和集群访问权限。使用 `kubectl cluster-info` 验证。

---

## 集群上下文

在运行任何命令之前，你需要知道目标是哪个集群和命名空间。Kubernetes支持多个上下文，允许你从同一终端在开发、预发布和生产集群之间切换。在这里犯错可能意味着将测试代码部署到生产环境，所以务必先验证你的上下文。

### 上下文管理

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

### 集群信息

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

## Pod

Pod是Kubernetes中最小的可部署单元——一组共享存储和网络资源的一个或多个容器。实际上，大多数Pod只包含一个容器，但Sidecar模式（日志代理、代理）使用多容器Pod。理解Pod管理是基础，因为Kubernetes中的所有工作负载最终都以Pod形式运行。

### 列出和检查Pod

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

### 创建和管理Pod

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

### Pod日志和调试

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

## Deployment

Deployment是在Kubernetes中运行无状态应用的标准方式。它们管理ReplicaSet，而ReplicaSet又管理Pod——提供声明式更新、滚动部署和自动回滚。当你更新Deployment的镜像或配置时，Kubernetes会逐步用新Pod替换旧Pod，确保零停机部署。这是你在生产中最常使用的资源。

### 管理Deployment

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

### 扩展

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### 更新和回滚

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

## Service

Service为你的Pod提供稳定的网络端点。由于Pod是临时的，重新创建时会获得新的IP地址，你不能依赖Pod IP进行通信。Service创建一个持久的虚拟IP和DNS名称，将流量路由到正确的Pod，无论存在多少副本或它们被调度到哪里。这就是Kubernetes集群内服务相互发现和通信的方式。

### 创建和管理Service

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

### DNS和服务发现

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

## ConfigMap和Secret

ConfigMap存储非敏感配置数据（环境变量、配置文件），而Secret存储敏感数据（密码、API密钥、TLS证书）。两者都将配置与容器镜像解耦，允许你在不重建或重新部署应用的情况下更改设置。在生产环境中，Secret应始终在静态时加密，并通过RBAC进行访问控制。

### ConfigMap

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

### Secret

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

## 集群调试

Kubernetes中的生产调试需要知道在哪里查看。Pod崩溃了？检查事件和日志。服务不可达？检查端点和网络策略。节点无响应？检查节点状况和资源压力。本节包含在生产故障中拯救了无数值班工程师的命令。

### 诊断命令

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

### Pod调试

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

### 命名空间管理

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
