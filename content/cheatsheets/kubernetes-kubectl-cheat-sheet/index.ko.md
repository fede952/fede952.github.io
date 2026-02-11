---
title: "Kubernetes (K8s) & Kubectl: 프로덕션 클러스터 명령어"
description: "프로덕션 환경에서 Kubernetes 클러스터를 관리하기 위한 필수 kubectl 명령어. Pod 관리, 디플로이먼트, 서비스, ConfigMap, 시크릿 및 클러스터 디버깅 기법을 다룹니다."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl 치트시트", "k8s 명령어", "Pod 관리 kubernetes", "디플로이먼트 스케일링 k8s", "kubernetes 디버깅", "kubectl get pods", "kubernetes 서비스 노출", "configmap secrets k8s", "kubernetes 클러스터 관리", "kubectl logs 문제 해결"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: 프로덕션 클러스터 명령어",
    "description": "Kubernetes 클러스터 관리를 위한 필수 kubectl 명령어: Pod, 디플로이먼트, 서비스, ConfigMap 및 디버깅.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Kubernetes는 클라우드의 운영 체제입니다. 머신 클러스터 전반에서 컨테이너를 오케스트레이션하며 스케일링, 자가 복구, 로드 밸런싱, 서비스 디스커버리를 자동으로 처리합니다. 하지만 이 모든 강력한 기능은 하나의 커맨드라인 도구인 `kubectl`을 통해 접근합니다. 이 필드 매뉴얼에는 클러스터 관리의 모든 단계에 필요한 kubectl 명령어가 포함되어 있습니다 — 첫 번째 Pod 배포부터 새벽 3시 프로덕션 장애 디버깅까지. 모든 명령어는 프로덕션에서 테스트되었으며 워크플로우별로 정리되어 있어 필요한 것을 몇 초 만에 찾을 수 있습니다.

모든 명령어는 유효한 kubeconfig와 클러스터 접근 권한이 있다고 가정합니다. `kubectl cluster-info`로 확인하세요.

---

## 클러스터 컨텍스트

명령어를 실행하기 전에 어떤 클러스터와 네임스페이스를 대상으로 하는지 알아야 합니다. Kubernetes는 여러 컨텍스트를 지원하여 같은 터미널에서 개발, 스테이징, 프로덕션 클러스터 간에 전환할 수 있습니다. 여기서 실수하면 테스트 코드를 프로덕션에 배포하는 결과를 초래할 수 있으므로, 항상 먼저 컨텍스트를 확인하세요.

### 컨텍스트 관리

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

### 클러스터 정보

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

Pod는 Kubernetes에서 가장 작은 배포 가능한 단위입니다 — 스토리지와 네트워크 리소스를 공유하는 하나 이상의 컨테이너 그룹입니다. 실제로 대부분의 Pod는 단일 컨테이너를 포함하지만, 사이드카 패턴(로깅 에이전트, 프록시)은 멀티 컨테이너 Pod를 사용합니다. Kubernetes의 모든 워크로드는 궁극적으로 Pod로 실행되기 때문에 Pod 관리를 이해하는 것이 기본입니다.

### Pod 목록 및 검사

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

### Pod 생성 및 관리

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

### Pod 로그 및 디버깅

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

## 디플로이먼트

디플로이먼트는 Kubernetes에서 스테이트리스 애플리케이션을 실행하는 표준 방법입니다. ReplicaSet를 관리하고, ReplicaSet은 Pod를 관리합니다 — 선언적 업데이트, 롤링 배포, 자동 롤백을 제공합니다. 디플로이먼트의 이미지나 구성을 업데이트하면 Kubernetes가 이전 Pod를 새 Pod로 점진적으로 교체하여 무중단 배포를 보장합니다. 이것은 프로덕션에서 가장 많이 사용할 리소스입니다.

### 디플로이먼트 관리

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

### 스케일링

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### 업데이트 및 롤백

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

## 서비스

서비스는 Pod에 안정적인 네트워크 엔드포인트를 제공합니다. Pod는 일시적이며 재생성 시 새로운 IP 주소를 받기 때문에 통신에 Pod IP를 사용할 수 없습니다. Service는 레플리카 수나 스케줄링 위치에 관계없이 올바른 Pod로 트래픽을 라우팅하는 영구 가상 IP와 DNS 이름을 생성합니다. 이것이 Kubernetes 클러스터 내에서 서비스가 서로를 발견하고 통신하는 방법입니다.

### 서비스 생성 및 관리

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

### DNS 및 서비스 디스커버리

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

## ConfigMap과 Secret

ConfigMap은 비민감 설정 데이터(환경 변수, 설정 파일)를 저장하고, Secret은 민감 데이터(비밀번호, API 키, TLS 인증서)를 저장합니다. 둘 다 구성을 컨테이너 이미지에서 분리하여 애플리케이션을 다시 빌드하거나 재배포하지 않고도 설정을 변경할 수 있게 합니다. 프로덕션에서 Secret은 항상 저장 시 암호화되어야 하며 RBAC을 통해 접근이 제어되어야 합니다.

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

## 클러스터 디버깅

Kubernetes에서의 프로덕션 디버깅은 어디를 봐야 하는지 아는 것이 중요합니다. Pod가 크래시하나요? 이벤트와 로그를 확인하세요. 서비스에 접근할 수 없나요? 엔드포인트와 네트워크 정책을 확인하세요. 노드가 응답하지 않나요? 노드 상태와 리소스 압박을 확인하세요. 이 섹션에는 프로덕션 장애 중 수많은 온콜 엔지니어를 구한 명령어들이 포함되어 있습니다.

### 진단 명령어

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

### Pod 디버깅

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

### 네임스페이스 관리

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
