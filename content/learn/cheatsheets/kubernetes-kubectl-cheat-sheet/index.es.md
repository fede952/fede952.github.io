---
title: "Kubernetes (K8s) & Kubectl: Comandos para Clústeres en Producción"
description: "Comandos esenciales de kubectl para gestionar clústeres de Kubernetes en producción. Cubre gestión de pods, deployments, servicios, ConfigMaps, secrets y técnicas de depuración de clústeres."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl cheat sheet", "comandos k8s", "gestión de pods kubernetes", "escalado de deployments k8s", "depuración kubernetes", "kubectl get pods", "exponer servicios kubernetes", "configmap secrets k8s", "administración de clústeres kubernetes", "kubectl logs solución de problemas"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: Comandos para Clústeres en Producción",
    "description": "Comandos esenciales de kubectl para gestionar clústeres Kubernetes: pods, deployments, servicios, ConfigMaps y depuración.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Inicio del Sistema

Kubernetes es el sistema operativo de la nube. Orquesta contenedores a través de clústeres de máquinas, gestionando escalado, auto-recuperación, balanceo de carga y descubrimiento de servicios de forma automática. Pero toda esa potencia se accede a través de una única herramienta de línea de comandos: `kubectl`. Este manual de campo contiene los comandos kubectl que necesitas para cada fase de la gestión del clúster — desde desplegar tu primer pod hasta depurar incidentes en producción a las 3 de la madrugada. Cada comando está probado en producción y organizado por flujo de trabajo, para que puedas encontrar lo que necesitas en segundos.

Todos los comandos asumen que tienes un kubeconfig válido y acceso al clúster. Verifica con `kubectl cluster-info`.

---

## Contexto del Clúster

Antes de ejecutar cualquier comando, necesitas saber a qué clúster y namespace estás apuntando. Kubernetes soporta múltiples contextos, permitiéndote cambiar entre clústeres de desarrollo, staging y producción desde el mismo terminal. Equivocarte aquí puede significar desplegar código de pruebas en producción, así que siempre verifica tu contexto primero.

### Gestión de contextos

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

### Información del clúster

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

Los pods son la unidad desplegable más pequeña en Kubernetes — un grupo de uno o más contenedores que comparten recursos de almacenamiento y red. En la práctica, la mayoría de los pods contienen un solo contenedor, pero los patrones sidecar (agentes de logging, proxies) utilizan pods multi-contenedor. Entender la gestión de pods es fundamental porque toda carga de trabajo en Kubernetes finalmente se ejecuta como un pod.

### Listar e inspeccionar pods

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

### Crear y gestionar pods

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

### Logs y depuración de pods

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

Los deployments son la forma estándar de ejecutar aplicaciones stateless en Kubernetes. Gestionan ReplicaSets, que a su vez gestionan pods — proporcionando actualizaciones declarativas, despliegues rolling y rollbacks automáticos. Cuando actualizas la imagen o configuración de un deployment, Kubernetes reemplaza gradualmente los pods antiguos por nuevos, asegurando despliegues sin tiempo de inactividad. Este es el recurso que más usarás en producción.

### Gestionar deployments

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

### Escalado

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### Actualizaciones y rollbacks

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

## Servicios

Los servicios proporcionan endpoints de red estables para tus pods. Dado que los pods son efímeros y obtienen nuevas direcciones IP cuando se recrean, no puedes confiar en las IPs de los pods para la comunicación. Un Service crea una IP virtual persistente y un nombre DNS que enruta el tráfico hacia los pods correctos, independientemente de cuántas réplicas existan o dónde estén programadas. Así es como los servicios se descubren y comunican entre sí dentro de un clúster Kubernetes.

### Crear y gestionar servicios

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

### DNS y descubrimiento de servicios

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

## ConfigMaps y Secrets

Los ConfigMaps almacenan datos de configuración no sensibles (variables de entorno, archivos de configuración), mientras que los Secrets almacenan datos sensibles (contraseñas, claves API, certificados TLS). Ambos desacoplan la configuración de las imágenes de los contenedores, permitiéndote cambiar configuraciones sin reconstruir ni redesplegar tu aplicación. En producción, los Secrets siempre deben estar cifrados en reposo y con control de acceso mediante RBAC.

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

## Depuración de Clústeres

La depuración en producción en Kubernetes requiere saber dónde buscar. ¿Pods fallando? Revisa eventos y logs. ¿Servicio inaccesible? Revisa endpoints y políticas de red. ¿Nodo sin respuesta? Revisa las condiciones del nodo y la presión de recursos. Esta sección contiene los comandos que han salvado a innumerables ingenieros de guardia durante incidentes en producción.

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

### Depuración de pods

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

### Gestión de namespaces

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
