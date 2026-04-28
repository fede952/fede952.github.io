---
title: "Kubernetes (K8s) & Kubectl : Commandes pour Clusters en Production"
description: "Commandes kubectl essentielles pour gérer les clusters Kubernetes en production. Couvre la gestion des pods, les déploiements, les services, les ConfigMaps, les secrets et les techniques de débogage de cluster."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl aide-mémoire", "commandes k8s", "gestion des pods kubernetes", "mise à l'échelle déploiement k8s", "débogage kubernetes", "kubectl get pods", "exposer service kubernetes", "configmap secrets k8s", "administration cluster kubernetes", "kubectl logs dépannage"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl : Commandes pour Clusters en Production",
    "description": "Commandes kubectl essentielles pour gérer les clusters Kubernetes : pods, déploiements, services, ConfigMaps et débogage.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Kubernetes est le système d'exploitation du cloud. Il orchestre les conteneurs à travers des clusters de machines, gérant la mise à l'échelle, l'auto-réparation, l'équilibrage de charge et la découverte de services automatiquement. Mais toute cette puissance est accessible via un seul outil en ligne de commande : `kubectl`. Ce manuel de terrain contient les commandes kubectl dont vous avez besoin pour chaque phase de la gestion de cluster — du déploiement de votre premier pod au débogage d'incidents en production à 3 heures du matin. Chaque commande est testée en production et organisée par flux de travail, pour que vous puissiez trouver ce dont vous avez besoin en quelques secondes.

Toutes les commandes supposent que vous disposez d'un kubeconfig valide et d'un accès au cluster. Vérifiez avec `kubectl cluster-info`.

---

## Contexte du Cluster

Avant d'exécuter toute commande, vous devez savoir quel cluster et quel namespace vous ciblez. Kubernetes prend en charge plusieurs contextes, vous permettant de basculer entre les clusters de développement, de staging et de production depuis le même terminal. Se tromper ici peut signifier déployer du code de test en production, alors vérifiez toujours votre contexte d'abord.

### Gestion des contextes

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

### Informations sur le cluster

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

Les pods sont la plus petite unité déployable dans Kubernetes — un groupe d'un ou plusieurs conteneurs partageant les ressources de stockage et de réseau. En pratique, la plupart des pods contiennent un seul conteneur, mais les patterns sidecar (agents de logging, proxies) utilisent des pods multi-conteneurs. Comprendre la gestion des pods est fondamental car chaque charge de travail dans Kubernetes s'exécute finalement en tant que pod.

### Lister et inspecter les pods

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

### Créer et gérer les pods

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

### Logs et débogage des pods

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

## Déploiements

Les déploiements sont le moyen standard d'exécuter des applications stateless dans Kubernetes. Ils gèrent les ReplicaSets, qui à leur tour gèrent les pods — offrant des mises à jour déclaratives, des déploiements progressifs et des rollbacks automatiques. Lorsque vous mettez à jour l'image ou la configuration d'un déploiement, Kubernetes remplace progressivement les anciens pods par de nouveaux, garantissant des déploiements sans interruption de service. C'est la ressource que vous utiliserez le plus en production.

### Gérer les déploiements

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

### Mise à l'échelle

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Mises à jour et rollbacks

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

Les services fournissent des endpoints réseau stables pour vos pods. Puisque les pods sont éphémères et obtiennent de nouvelles adresses IP lorsqu'ils sont recréés, vous ne pouvez pas compter sur les IP des pods pour la communication. Un Service crée une IP virtuelle persistante et un nom DNS qui achemine le trafic vers les pods corrects, quel que soit le nombre de répliques existantes ou leur emplacement. C'est ainsi que les services se découvrent et communiquent entre eux au sein d'un cluster Kubernetes.

### Créer et gérer les services

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

### DNS et découverte de services

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

## ConfigMaps et Secrets

Les ConfigMaps stockent les données de configuration non sensibles (variables d'environnement, fichiers de configuration), tandis que les Secrets stockent les données sensibles (mots de passe, clés API, certificats TLS). Les deux découplent la configuration des images de conteneurs, vous permettant de modifier les paramètres sans reconstruire ni redéployer votre application. En production, les Secrets doivent toujours être chiffrés au repos et contrôlés en accès via RBAC.

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

## Débogage des Clusters

Le débogage en production dans Kubernetes nécessite de savoir où chercher. Des pods qui plantent ? Vérifiez les événements et les logs. Service inaccessible ? Vérifiez les endpoints et les politiques réseau. Noeud qui ne répond pas ? Vérifiez les conditions du noeud et la pression des ressources. Cette section contient les commandes qui ont sauvé d'innombrables ingénieurs d'astreinte lors d'incidents en production.

### Commandes de diagnostic

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

### Débogage des pods

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

### Gestion des namespaces

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
