---
title: "Kubernetes (K8s) & Kubectl: Команды для продакшн-кластеров"
description: "Основные команды kubectl для управления кластерами Kubernetes в продакшне. Охватывает управление подами, деплойменты, сервисы, ConfigMap, секреты и методы отладки кластеров."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl шпаргалка", "команды k8s", "управление подами kubernetes", "масштабирование деплойментов k8s", "отладка kubernetes", "kubectl get pods", "expose сервисов kubernetes", "configmap secrets k8s", "администрирование кластера kubernetes", "kubectl logs устранение неполадок"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: Команды для продакшн-кластеров",
    "description": "Основные команды kubectl для управления кластерами Kubernetes: поды, деплойменты, сервисы, ConfigMap и отладка.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Инициализация системы

Kubernetes — это операционная система облака. Он оркестрирует контейнеры по кластерам машин, автоматически обеспечивая масштабирование, самовосстановление, балансировку нагрузки и обнаружение сервисов. Но вся эта мощь доступна через единственный инструмент командной строки: `kubectl`. Это полевое руководство содержит команды kubectl, необходимые на каждом этапе управления кластером — от развёртывания первого пода до отладки продакшн-инцидентов в 3 часа ночи. Каждая команда проверена на продакшне и организована по рабочим процессам, чтобы вы могли найти нужное за секунды.

Все команды предполагают наличие действующего kubeconfig и доступа к кластеру. Проверьте с помощью `kubectl cluster-info`.

---

## Контекст кластера

Прежде чем выполнять любую команду, нужно знать, на какой кластер и namespace вы нацелены. Kubernetes поддерживает несколько контекстов, позволяя переключаться между кластерами разработки, staging и продакшна из одного терминала. Ошибка здесь может привести к развёртыванию тестового кода в продакшн, поэтому всегда проверяйте контекст в первую очередь.

### Управление контекстами

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

### Информация о кластере

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

## Поды

Поды — это наименьшая развёртываемая единица в Kubernetes — группа из одного или нескольких контейнеров, разделяющих ресурсы хранения и сети. На практике большинство подов содержат один контейнер, но паттерны sidecar (агенты логирования, прокси) используют многоконтейнерные поды. Понимание управления подами является фундаментальным, поскольку каждая рабочая нагрузка в Kubernetes в конечном итоге выполняется как под.

### Просмотр и инспектирование подов

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

### Создание и управление подами

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

### Логи и отладка подов

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

## Деплойменты

Деплойменты — это стандартный способ запуска stateless-приложений в Kubernetes. Они управляют ReplicaSet, которые, в свою очередь, управляют подами — обеспечивая декларативные обновления, постепенные развёртывания и автоматические откаты. Когда вы обновляете образ или конфигурацию деплоймента, Kubernetes постепенно заменяет старые поды новыми, обеспечивая развёртывание без простоев. Это ресурс, который вы будете использовать чаще всего в продакшне.

### Управление деплойментами

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

### Масштабирование

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Обновления и откаты

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

## Сервисы

Сервисы обеспечивают стабильные сетевые эндпоинты для ваших подов. Поскольку поды эфемерны и получают новые IP-адреса при пересоздании, вы не можете полагаться на IP подов для коммуникации. Service создаёт постоянный виртуальный IP и DNS-имя, которые маршрутизируют трафик к правильным подам, независимо от количества реплик или их расположения. Так сервисы обнаруживают друг друга и обмениваются данными внутри кластера Kubernetes.

### Создание и управление сервисами

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

### DNS и обнаружение сервисов

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

## ConfigMap и Secrets

ConfigMap хранят несекретные данные конфигурации (переменные окружения, файлы конфигурации), а Secrets хранят конфиденциальные данные (пароли, API-ключи, TLS-сертификаты). Оба ресурса отделяют конфигурацию от образов контейнеров, позволяя изменять настройки без пересборки или повторного развёртывания приложения. В продакшне Secrets всегда должны быть зашифрованы в состоянии покоя и контролироваться через RBAC.

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

## Отладка кластеров

Отладка в продакшне в Kubernetes требует знания, где искать. Поды падают? Проверьте события и логи. Сервис недоступен? Проверьте эндпоинты и сетевые политики. Нода не отвечает? Проверьте состояние ноды и давление на ресурсы. В этом разделе собраны команды, которые спасли бесчисленное количество дежурных инженеров во время продакшн-инцидентов.

### Диагностические команды

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

### Отладка подов

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

### Управление пространствами имён

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
