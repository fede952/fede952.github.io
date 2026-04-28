---
title: "Kubernetes (K8s) & Kubectl：本番クラスターコマンド集"
description: "本番環境でKubernetesクラスターを管理するための必須kubectlコマンド。Pod管理、デプロイメント、サービス、ConfigMap、シークレット、クラスターデバッグ技術をカバーします。"
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl チートシート", "k8s コマンド", "Pod管理 kubernetes", "デプロイメント スケーリング k8s", "kubernetes デバッグ", "kubectl get pods", "kubernetes サービス公開", "configmap secrets k8s", "kubernetes クラスター管理", "kubectl logs トラブルシューティング"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl：本番クラスターコマンド集",
    "description": "Kubernetesクラスター管理のための必須kubectlコマンド：Pod、デプロイメント、サービス、ConfigMap、デバッグ。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## システム初期化

Kubernetesはクラウドのオペレーティングシステムです。マシンのクラスター全体でコンテナをオーケストレーションし、スケーリング、自己修復、ロードバランシング、サービスディスカバリーを自動的に処理します。しかし、そのすべてのパワーは単一のコマンドラインツール `kubectl` を通じてアクセスされます。このフィールドマニュアルには、クラスター管理のあらゆるフェーズで必要なkubectlコマンドが含まれています——最初のPodのデプロイから、深夜3時の本番インシデントのデバッグまで。すべてのコマンドは本番環境でテスト済みで、ワークフロー別に整理されているため、必要なものを数秒で見つけることができます。

すべてのコマンドは有効なkubeconfigとクラスターアクセスがあることを前提としています。`kubectl cluster-info` で確認してください。

---

## クラスターコンテキスト

コマンドを実行する前に、どのクラスターとネームスペースをターゲットにしているかを把握する必要があります。Kubernetesは複数のコンテキストをサポートしており、同じターミナルから開発、ステージング、本番クラスターを切り替えることができます。ここでの間違いはテストコードを本番にデプロイしてしまうことを意味するため、常にまずコンテキストを確認してください。

### コンテキスト管理

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

### クラスター情報

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

PodはKubernetesにおける最小のデプロイ可能な単位です——ストレージとネットワークリソースを共有する1つ以上のコンテナのグループです。実際には、ほとんどのPodは単一のコンテナを含みますが、サイドカーパターン（ロギングエージェント、プロキシ）ではマルチコンテナPodを使用します。Kubernetesのすべてのワークロードは最終的にPodとして実行されるため、Pod管理を理解することは基本です。

### Podの一覧と検査

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

### Podの作成と管理

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

### Podのログとデバッグ

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

## デプロイメント

デプロイメントはKubernetesでステートレスアプリケーションを実行する標準的な方法です。ReplicaSetを管理し、ReplicaSetがPodを管理します——宣言的な更新、ローリングデプロイメント、自動ロールバックを提供します。デプロイメントのイメージや設定を更新すると、Kubernetesは古いPodを新しいPodに段階的に置き換え、ダウンタイムなしのデプロイメントを保証します。これは本番環境で最も多く使用するリソースです。

### デプロイメントの管理

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

### スケーリング

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### 更新とロールバック

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

## サービス

サービスはPodに安定したネットワークエンドポイントを提供します。Podは一時的なもので、再作成時に新しいIPアドレスを取得するため、通信にPodのIPを頼ることはできません。ServiceはPodの数や配置場所に関係なく、正しいPodにトラフィックをルーティングする永続的な仮想IPとDNS名を作成します。これがKubernetesクラスター内でサービスが互いを発見し通信する方法です。

### サービスの作成と管理

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

### DNSとサービスディスカバリー

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

## ConfigMapとSecret

ConfigMapは機密でない設定データ（環境変数、設定ファイル）を保存し、Secretは機密データ（パスワード、APIキー、TLS証明書）を保存します。どちらもコンテナイメージから設定を分離し、アプリケーションを再ビルドや再デプロイすることなく設定を変更できるようにします。本番環境では、Secretは常に保存時に暗号化され、RBACによるアクセス制御が必要です。

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

## クラスターのデバッグ

Kubernetesでの本番デバッグは、どこを見るべきかを知ることが重要です。Podがクラッシュしている？イベントとログを確認してください。サービスに到達できない？エンドポイントとネットワークポリシーを確認してください。ノードが応答しない？ノードの状態とリソースの圧迫を確認してください。このセクションには、本番インシデント中に数え切れないほどのオンコールエンジニアを救ってきたコマンドが含まれています。

### 診断コマンド

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

### Podのデバッグ

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

### ネームスペース管理

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
