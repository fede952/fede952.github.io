---
title: "Kubernetes (K8s) & Kubectl: Produktions-Cluster-Befehle"
description: "Essentielle kubectl-Befehle für die Verwaltung von Kubernetes-Clustern in der Produktion. Umfasst Pod-Management, Deployments, Services, ConfigMaps, Secrets und Cluster-Debugging-Techniken."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl Spickzettel", "k8s Befehle", "Pod-Management Kubernetes", "Deployment Skalierung k8s", "Kubernetes Debugging", "kubectl get pods", "Kubernetes Service exponieren", "ConfigMap Secrets k8s", "Kubernetes Cluster-Administration", "kubectl logs Fehlerbehebung"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: Produktions-Cluster-Befehle",
    "description": "Essentielle kubectl-Befehle für die Verwaltung von Kubernetes-Clustern: Pods, Deployments, Services, ConfigMaps und Debugging.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

Kubernetes ist das Betriebssystem der Cloud. Es orchestriert Container über Cluster von Maschinen hinweg und übernimmt automatisch Skalierung, Selbstheilung, Lastverteilung und Service-Erkennung. Aber all diese Leistung wird über ein einziges Kommandozeilen-Tool gesteuert: `kubectl`. Dieses Feldhandbuch enthält die kubectl-Befehle, die Sie für jede Phase der Cluster-Verwaltung benötigen — vom Deployment Ihres ersten Pods bis zum Debugging von Produktionsvorfällen um 3 Uhr morgens. Jeder Befehl ist in der Produktion getestet und nach Arbeitsabläufen organisiert, damit Sie in Sekunden finden, was Sie brauchen.

Alle Befehle setzen eine gültige kubeconfig und Cluster-Zugang voraus. Überprüfen Sie dies mit `kubectl cluster-info`.

---

## Cluster-Kontext

Bevor Sie einen Befehl ausführen, müssen Sie wissen, welchen Cluster und Namespace Sie ansteuern. Kubernetes unterstützt mehrere Kontexte, sodass Sie vom selben Terminal aus zwischen Entwicklungs-, Staging- und Produktions-Clustern wechseln können. Ein Fehler hier kann bedeuten, dass Testcode in die Produktion deployed wird — überprüfen Sie also immer zuerst Ihren Kontext.

### Kontextverwaltung

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

### Cluster-Informationen

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

Pods sind die kleinste deploybare Einheit in Kubernetes — eine Gruppe von einem oder mehreren Containern, die sich Speicher- und Netzwerkressourcen teilen. In der Praxis enthalten die meisten Pods einen einzelnen Container, aber Sidecar-Muster (Logging-Agenten, Proxies) verwenden Multi-Container-Pods. Das Verständnis der Pod-Verwaltung ist grundlegend, da jede Arbeitslast in Kubernetes letztendlich als Pod ausgeführt wird.

### Pods auflisten und inspizieren

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

### Pods erstellen und verwalten

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

### Pod-Logs und Debugging

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

Deployments sind der Standardweg, um zustandslose Anwendungen in Kubernetes auszuführen. Sie verwalten ReplicaSets, die wiederum Pods verwalten — und bieten deklarative Updates, Rolling Deployments und automatische Rollbacks. Wenn Sie das Image oder die Konfiguration eines Deployments aktualisieren, ersetzt Kubernetes schrittweise alte Pods durch neue und gewährleistet so Deployments ohne Ausfallzeit. Dies ist die Ressource, die Sie in der Produktion am häufigsten verwenden werden.

### Deployments verwalten

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

### Skalierung

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Updates und Rollbacks

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

Services bieten stabile Netzwerk-Endpunkte für Ihre Pods. Da Pods kurzlebig sind und neue IP-Adressen erhalten, wenn sie neu erstellt werden, können Sie sich nicht auf Pod-IPs für die Kommunikation verlassen. Ein Service erstellt eine persistente virtuelle IP und einen DNS-Namen, der den Datenverkehr an die richtigen Pods weiterleitet, unabhängig davon, wie viele Replikate existieren oder wo sie eingeplant sind. So entdecken und kommunizieren Services miteinander innerhalb eines Kubernetes-Clusters.

### Services erstellen und verwalten

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

### DNS und Service-Erkennung

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

## ConfigMaps und Secrets

ConfigMaps speichern nicht-sensible Konfigurationsdaten (Umgebungsvariablen, Konfigurationsdateien), während Secrets sensible Daten speichern (Passwörter, API-Schlüssel, TLS-Zertifikate). Beide entkoppeln die Konfiguration von Container-Images, sodass Sie Einstellungen ändern können, ohne Ihre Anwendung neu zu erstellen oder erneut zu deployen. In der Produktion sollten Secrets immer im Ruhezustand verschlüsselt und über RBAC zugriffskontrolliert sein.

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

## Cluster-Debugging

Produktions-Debugging in Kubernetes erfordert, dass man weiß, wo man suchen muss. Pods stürzen ab? Überprüfen Sie Ereignisse und Logs. Service nicht erreichbar? Überprüfen Sie Endpunkte und Netzwerkrichtlinien. Knoten reagiert nicht? Überprüfen Sie Knotenbedingungen und Ressourcendruck. Dieser Abschnitt enthält die Befehle, die zahllosen Bereitschaftsingenieuren bei Produktionsvorfällen das Leben gerettet haben.

### Diagnosebefehle

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

### Pod-Debugging

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

### Namespace-Verwaltung

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
