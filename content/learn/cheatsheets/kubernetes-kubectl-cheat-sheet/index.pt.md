---
title: "Kubernetes (K8s) & Kubectl: Comandos para Clusters em Produção"
description: "Comandos essenciais do kubectl para gerenciar clusters Kubernetes em produção. Abrange gerenciamento de pods, deployments, serviços, ConfigMaps, secrets e técnicas de depuração de clusters."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl folha de referência", "comandos k8s", "gerenciamento de pods kubernetes", "escalabilidade de deployment k8s", "depuração kubernetes", "kubectl get pods", "expor serviço kubernetes", "configmap secrets k8s", "administração de cluster kubernetes", "kubectl logs solução de problemas"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: Comandos para Clusters em Produção",
    "description": "Comandos essenciais do kubectl para gerenciar clusters Kubernetes: pods, deployments, serviços, ConfigMaps e depuração.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

Kubernetes é o sistema operacional da nuvem. Ele orquestra contêineres através de clusters de máquinas, gerenciando escalabilidade, auto-recuperação, balanceamento de carga e descoberta de serviços automaticamente. Mas todo esse poder é acessado através de uma única ferramenta de linha de comando: `kubectl`. Este manual de campo contém os comandos kubectl que você precisa para cada fase do gerenciamento de cluster — desde o deploy do seu primeiro pod até a depuração de incidentes em produção às 3 da manhã. Cada comando é testado em produção e organizado por fluxo de trabalho, para que você encontre o que precisa em segundos.

Todos os comandos assumem que você tem um kubeconfig válido e acesso ao cluster. Verifique com `kubectl cluster-info`.

---

## Contexto do Cluster

Antes de executar qualquer comando, você precisa saber qual cluster e namespace está utilizando. O Kubernetes suporta múltiplos contextos, permitindo alternar entre clusters de desenvolvimento, staging e produção a partir do mesmo terminal. Errar aqui pode significar fazer deploy de código de teste em produção, então sempre verifique seu contexto primeiro.

### Gerenciamento de contextos

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

### Informações do cluster

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

Pods são a menor unidade implantável no Kubernetes — um grupo de um ou mais contêineres que compartilham recursos de armazenamento e rede. Na prática, a maioria dos pods contém um único contêiner, mas os padrões sidecar (agentes de logging, proxies) usam pods multi-contêiner. Entender o gerenciamento de pods é fundamental porque toda carga de trabalho no Kubernetes acaba sendo executada como um pod.

### Listar e inspecionar pods

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

### Criar e gerenciar pods

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

### Logs e depuração de pods

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

Deployments são a forma padrão de executar aplicações stateless no Kubernetes. Eles gerenciam ReplicaSets, que por sua vez gerenciam pods — oferecendo atualizações declarativas, deploys progressivos e rollbacks automáticos. Quando você atualiza a imagem ou configuração de um deployment, o Kubernetes substitui gradualmente os pods antigos por novos, garantindo deploys sem tempo de inatividade. Este é o recurso que você mais usará em produção.

### Gerenciar deployments

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

### Escalabilidade

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Atualizações e rollbacks

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

## Serviços

Os serviços fornecem endpoints de rede estáveis para seus pods. Como os pods são efêmeros e recebem novos endereços IP quando recriados, você não pode depender dos IPs dos pods para comunicação. Um Service cria um IP virtual persistente e um nome DNS que roteia o tráfego para os pods corretos, independentemente de quantas réplicas existam ou onde estejam agendadas. É assim que os serviços se descobrem e se comunicam entre si dentro de um cluster Kubernetes.

### Criar e gerenciar serviços

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

### DNS e descoberta de serviços

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

## ConfigMaps e Secrets

ConfigMaps armazenam dados de configuração não sensíveis (variáveis de ambiente, arquivos de configuração), enquanto Secrets armazenam dados sensíveis (senhas, chaves de API, certificados TLS). Ambos desacoplam a configuração das imagens dos contêineres, permitindo alterar configurações sem reconstruir ou reimplantar sua aplicação. Em produção, os Secrets devem sempre ser criptografados em repouso e com controle de acesso via RBAC.

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

## Depuração de Clusters

A depuração em produção no Kubernetes exige saber onde procurar. Pods falhando? Verifique eventos e logs. Serviço inacessível? Verifique endpoints e políticas de rede. Nó sem resposta? Verifique as condições do nó e a pressão de recursos. Esta seção contém os comandos que salvaram incontáveis engenheiros de plantão durante incidentes em produção.

### Comandos de diagnóstico

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

### Depuração de pods

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

### Gerenciamento de namespaces

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
