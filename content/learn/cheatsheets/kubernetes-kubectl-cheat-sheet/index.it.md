---
title: "Kubernetes (K8s) & Kubectl: Comandi per Cluster in Produzione"
description: "Comandi kubectl essenziali per la gestione dei cluster Kubernetes in produzione. Copre gestione dei pod, deployment, servizi, ConfigMap, secret e tecniche di debug del cluster."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl cheat sheet", "comandi k8s", "gestione pod kubernetes", "scalabilità deployment k8s", "debug kubernetes", "kubectl get pods", "esporre servizi kubernetes", "configmap secret k8s", "amministrazione cluster kubernetes", "kubectl logs risoluzione problemi"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: Comandi per Cluster in Produzione",
    "description": "Comandi kubectl essenziali per la gestione dei cluster Kubernetes: pod, deployment, servizi, ConfigMap e debug.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

Kubernetes è il sistema operativo del cloud. Orchestra i container attraverso cluster di macchine, gestendo scalabilità, auto-riparazione, bilanciamento del carico e scoperta dei servizi in modo automatico. Ma tutta questa potenza è accessibile tramite un unico strumento da riga di comando: `kubectl`. Questo manuale operativo contiene i comandi kubectl necessari per ogni fase della gestione del cluster — dal deploy del primo pod al debug di incidenti in produzione alle 3 di notte. Ogni comando è testato in produzione e organizzato per flusso di lavoro, così puoi trovare ciò che ti serve in pochi secondi.

Tutti i comandi presuppongono un kubeconfig valido e l'accesso al cluster. Verifica con `kubectl cluster-info`.

---

## Contesto del Cluster

Prima di eseguire qualsiasi comando, devi sapere quale cluster e namespace stai utilizzando. Kubernetes supporta contesti multipli, permettendoti di passare da cluster di sviluppo, staging e produzione dallo stesso terminale. Un errore qui può significare deployare codice di test in produzione, quindi verifica sempre il tuo contesto prima di procedere.

### Gestione dei contesti

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

### Informazioni sul cluster

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

I pod sono la più piccola unità deployabile in Kubernetes — un gruppo di uno o più container che condividono risorse di storage e rete. In pratica, la maggior parte dei pod contiene un singolo container, ma i pattern sidecar (agenti di logging, proxy) utilizzano pod multi-container. Comprendere la gestione dei pod è fondamentale perché ogni carico di lavoro in Kubernetes alla fine viene eseguito come pod.

### Elencare e ispezionare i pod

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

### Creare e gestire i pod

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

### Log e debug dei pod

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

I deployment sono il modo standard per eseguire applicazioni stateless in Kubernetes. Gestiscono i ReplicaSet, che a loro volta gestiscono i pod — offrendo aggiornamenti dichiarativi, deploy rolling e rollback automatici. Quando aggiorni l'immagine o la configurazione di un deployment, Kubernetes sostituisce gradualmente i vecchi pod con quelli nuovi, garantendo deploy senza downtime. Questa è la risorsa che utilizzerai maggiormente in produzione.

### Gestire i deployment

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

### Scalabilità

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Aggiornamenti e rollback

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

## Servizi

I servizi forniscono endpoint di rete stabili per i tuoi pod. Poiché i pod sono effimeri e ottengono nuovi indirizzi IP quando vengono ricreati, non puoi fare affidamento sugli IP dei pod per la comunicazione. Un Service crea un IP virtuale persistente e un nome DNS che instrada il traffico verso i pod corretti, indipendentemente da quante repliche esistono o dove sono schedulati. Questo è il modo in cui i servizi si scoprono e comunicano tra loro all'interno di un cluster Kubernetes.

### Creare e gestire i servizi

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

### DNS e scoperta dei servizi

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

## ConfigMap e Secret

Le ConfigMap memorizzano dati di configurazione non sensibili (variabili d'ambiente, file di configurazione), mentre i Secret memorizzano dati sensibili (password, chiavi API, certificati TLS). Entrambi disaccoppiano la configurazione dalle immagini dei container, permettendoti di modificare le impostazioni senza ricostruire o ridistribuire l'applicazione. In produzione, i Secret dovrebbero sempre essere crittografati a riposo e controllati nell'accesso tramite RBAC.

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

## Debug dei Cluster

Il debug in produzione su Kubernetes richiede di sapere dove cercare. Pod che crashano? Controlla eventi e log. Servizio irraggiungibile? Controlla endpoint e network policy. Nodo che non risponde? Controlla le condizioni del nodo e la pressione sulle risorse. Questa sezione contiene i comandi che hanno salvato innumerevoli ingegneri di reperibilità durante incidenti in produzione.

### Comandi diagnostici

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

### Debug dei pod

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

### Gestione dei namespace

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
