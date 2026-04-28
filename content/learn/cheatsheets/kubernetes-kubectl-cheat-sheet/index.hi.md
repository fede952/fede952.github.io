---
title: "Kubernetes (K8s) & Kubectl: प्रोडक्शन क्लस्टर कमांड"
description: "प्रोडक्शन में Kubernetes क्लस्टर प्रबंधित करने के लिए आवश्यक kubectl कमांड। पॉड प्रबंधन, डिप्लॉयमेंट, सर्विस, ConfigMaps, सीक्रेट्स और क्लस्टर डिबगिंग तकनीकों को कवर करता है।"
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl चीट शीट", "k8s कमांड", "पॉड प्रबंधन kubernetes", "डिप्लॉयमेंट स्केलिंग k8s", "kubernetes डिबगिंग", "kubectl get pods", "kubernetes सर्विस एक्सपोज़", "configmap secrets k8s", "kubernetes क्लस्टर एडमिन", "kubectl logs समस्या निवारण"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) & Kubectl: प्रोडक्शन क्लस्टर कमांड",
    "description": "Kubernetes क्लस्टर प्रबंधन के लिए आवश्यक kubectl कमांड: पॉड, डिप्लॉयमेंट, सर्विस, ConfigMaps और डिबगिंग।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## सिस्टम इनिशियलाइज़ेशन

Kubernetes क्लाउड का ऑपरेटिंग सिस्टम है। यह मशीनों के क्लस्टर में कंटेनरों को ऑर्केस्ट्रेट करता है, स्केलिंग, सेल्फ-हीलिंग, लोड बैलेंसिंग और सर्विस डिस्कवरी को स्वचालित रूप से संभालता है। लेकिन यह सारी शक्ति एक ही कमांड-लाइन टूल के माध्यम से एक्सेस होती है: `kubectl`। यह फ़ील्ड मैनुअल क्लस्टर प्रबंधन के हर चरण के लिए आवश्यक kubectl कमांड प्रदान करता है — पहले पॉड को डिप्लॉय करने से लेकर रात 3 बजे प्रोडक्शन इंसिडेंट को डिबग करने तक। हर कमांड प्रोडक्शन में परीक्षित और वर्कफ़्लो के अनुसार व्यवस्थित है, ताकि आप सेकंडों में ज़रूरत की चीज़ खोज सकें।

सभी कमांड मानते हैं कि आपके पास वैध kubeconfig और क्लस्टर एक्सेस है। `kubectl cluster-info` से सत्यापित करें।

---

## क्लस्टर कॉन्टेक्स्ट

कोई भी कमांड चलाने से पहले, आपको जानना होगा कि आप किस क्लस्टर और नेमस्पेस को टार्गेट कर रहे हैं। Kubernetes कई कॉन्टेक्स्ट सपोर्ट करता है, जिससे आप एक ही टर्मिनल से डेवलपमेंट, स्टेजिंग और प्रोडक्शन क्लस्टर के बीच स्विच कर सकते हैं। यहाँ गलती करने का मतलब टेस्ट कोड को प्रोडक्शन में डिप्लॉय करना हो सकता है, इसलिए हमेशा पहले अपना कॉन्टेक्स्ट सत्यापित करें।

### कॉन्टेक्स्ट प्रबंधन

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

### क्लस्टर जानकारी

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

## पॉड

पॉड Kubernetes में सबसे छोटी डिप्लॉय करने योग्य इकाई है — स्टोरेज और नेटवर्क संसाधन साझा करने वाले एक या अधिक कंटेनरों का समूह। व्यवहार में, अधिकांश पॉड में एक ही कंटेनर होता है, लेकिन साइडकार पैटर्न (लॉगिंग एजेंट, प्रॉक्सी) मल्टी-कंटेनर पॉड का उपयोग करते हैं। पॉड प्रबंधन को समझना मौलिक है क्योंकि Kubernetes में हर वर्कलोड अंततः एक पॉड के रूप में चलता है।

### पॉड सूचीबद्ध और निरीक्षण करें

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

### पॉड बनाएँ और प्रबंधित करें

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

### पॉड लॉग और डिबगिंग

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

## डिप्लॉयमेंट

डिप्लॉयमेंट Kubernetes में स्टेटलेस एप्लिकेशन चलाने का मानक तरीका है। ये ReplicaSets को प्रबंधित करते हैं, जो बदले में पॉड को प्रबंधित करते हैं — डिक्लेरेटिव अपडेट, रोलिंग डिप्लॉयमेंट और ऑटोमैटिक रोलबैक प्रदान करते हैं। जब आप किसी डिप्लॉयमेंट की इमेज या कॉन्फ़िगरेशन अपडेट करते हैं, Kubernetes धीरे-धीरे पुराने पॉड को नए पॉड से बदलता है, ज़ीरो-डाउनटाइम डिप्लॉयमेंट सुनिश्चित करता है। यह वह संसाधन है जिसका उपयोग आप प्रोडक्शन में सबसे अधिक करेंगे।

### डिप्लॉयमेंट प्रबंधित करें

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

### स्केलिंग

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### अपडेट और रोलबैक

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

## सर्विस

सर्विस आपके पॉड के लिए स्थिर नेटवर्क एंडपॉइंट प्रदान करते हैं। चूँकि पॉड अल्पकालिक होते हैं और पुनर्निर्माण के समय नए IP पते प्राप्त करते हैं, आप संचार के लिए पॉड IP पर भरोसा नहीं कर सकते। एक Service एक स्थायी वर्चुअल IP और DNS नाम बनाता है जो ट्रैफ़िक को सही पॉड तक रूट करता है, चाहे कितनी भी रेप्लिकाएँ हों या वे कहीं भी शेड्यूल हों। इस तरह Kubernetes क्लस्टर के अंदर सर्विस एक-दूसरे को खोजते और संवाद करते हैं।

### सर्विस बनाएँ और प्रबंधित करें

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

### DNS और सर्विस डिस्कवरी

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

## ConfigMaps और Secrets

ConfigMaps गैर-संवेदनशील कॉन्फ़िगरेशन डेटा (एनवायरनमेंट वेरिएबल, कॉन्फ़िग फ़ाइलें) स्टोर करते हैं, जबकि Secrets संवेदनशील डेटा (पासवर्ड, API कुंजियाँ, TLS प्रमाणपत्र) स्टोर करते हैं। दोनों कॉन्फ़िगरेशन को कंटेनर इमेज से अलग करते हैं, जिससे आप बिना रीबिल्ड या रीडिप्लॉय किए सेटिंग्स बदल सकते हैं। प्रोडक्शन में, Secrets को हमेशा रेस्ट पर एन्क्रिप्टेड रखना चाहिए और RBAC के माध्यम से एक्सेस कंट्रोल किया जाना चाहिए।

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

## क्लस्टर डिबगिंग

Kubernetes में प्रोडक्शन डिबगिंग के लिए यह जानना ज़रूरी है कि कहाँ देखना है। पॉड क्रैश हो रहे हैं? इवेंट और लॉग जाँचें। सर्विस पहुँच योग्य नहीं? एंडपॉइंट और नेटवर्क पॉलिसी जाँचें। नोड अनरेस्पॉन्सिव? नोड की स्थिति और रिसोर्स प्रेशर जाँचें। इस अनुभाग में वे कमांड हैं जिन्होंने प्रोडक्शन इंसिडेंट के दौरान अनगिनत ऑन-कॉल इंजीनियरों को बचाया है।

### डायग्नोस्टिक कमांड

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

### पॉड डिबगिंग

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

### नेमस्पेस प्रबंधन

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
