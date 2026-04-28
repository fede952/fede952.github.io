---
title: "Kubernetes (K8s) و Kubectl: أوامر إدارة العناقيد في بيئة الإنتاج"
description: "أوامر kubectl الأساسية لإدارة عناقيد Kubernetes في بيئة الإنتاج. تشمل إدارة البودات والنشر والخدمات وConfigMaps والأسرار وتقنيات تصحيح أخطاء العناقيد."
date: 2026-02-10
tags: ["kubernetes", "cheatsheet", "devops", "kubectl", "cloud-native"]
keywords: ["kubectl ورقة مرجعية", "أوامر k8s", "إدارة البودات kubernetes", "توسيع النشر k8s", "تصحيح أخطاء kubernetes", "kubectl get pods", "كشف خدمات kubernetes", "configmap secrets k8s", "إدارة عناقيد kubernetes", "kubectl logs استكشاف الأخطاء"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) و Kubectl: أوامر إدارة العناقيد في بيئة الإنتاج",
    "description": "أوامر kubectl الأساسية لإدارة عناقيد Kubernetes: البودات والنشر والخدمات وConfigMaps وتصحيح الأخطاء.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## تهيئة النظام

Kubernetes هو نظام التشغيل السحابي. يقوم بتنسيق الحاويات عبر عناقيد من الأجهزة، ويتولى التوسع والإصلاح الذاتي وموازنة الأحمال واكتشاف الخدمات تلقائياً. لكن كل هذه القوة يتم الوصول إليها من خلال أداة سطر أوامر واحدة: `kubectl`. يحتوي هذا الدليل الميداني على أوامر kubectl التي تحتاجها لكل مرحلة من مراحل إدارة العنقود — من نشر أول بود إلى تصحيح أخطاء حوادث الإنتاج في الساعة 3 صباحاً. كل أمر مُختبر في بيئة الإنتاج ومنظم حسب سير العمل، لتتمكن من إيجاد ما تحتاجه في ثوانٍ.

تفترض جميع الأوامر أن لديك kubeconfig صالح وصلاحية الوصول للعنقود. تحقق باستخدام `kubectl cluster-info`.

---

## سياق العنقود

قبل تنفيذ أي أمر، تحتاج لمعرفة العنقود ومساحة الأسماء المستهدفة. يدعم Kubernetes سياقات متعددة، مما يسمح لك بالتبديل بين عناقيد التطوير والتجهيز والإنتاج من نفس الطرفية. الخطأ هنا قد يعني نشر كود اختبار في بيئة الإنتاج، لذا تحقق دائماً من السياق أولاً.

### إدارة السياقات

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

### معلومات العنقود

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

## البودات

البودات هي أصغر وحدة قابلة للنشر في Kubernetes — مجموعة من حاوية واحدة أو أكثر تتشارك في موارد التخزين والشبكة. في الممارسة العملية، تحتوي معظم البودات على حاوية واحدة، لكن أنماط sidecar (وكلاء التسجيل، البروكسيات) تستخدم بودات متعددة الحاويات. فهم إدارة البودات أمر أساسي لأن كل حمل عمل في Kubernetes يعمل في النهاية كبود.

### عرض وفحص البودات

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

### إنشاء وإدارة البودات

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

### سجلات البودات وتصحيح الأخطاء

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

## النشر (Deployments)

النشر هو الطريقة القياسية لتشغيل التطبيقات عديمة الحالة في Kubernetes. تدير ReplicaSets التي بدورها تدير البودات — مما يوفر تحديثات تصريحية ونشراً تدريجياً وتراجعاً تلقائياً. عندما تقوم بتحديث صورة أو إعدادات النشر، يستبدل Kubernetes تدريجياً البودات القديمة بأخرى جديدة، مما يضمن نشراً بدون توقف. هذا هو المورد الذي ستستخدمه أكثر في بيئة الإنتاج.

### إدارة النشر

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

### التوسع

```bash
# Scale a deployment to a specific number of replicas
kubectl scale deployment my-app --replicas=5

# Autoscale based on CPU usage (min 2, max 10 pods, target 50% CPU)
kubectl autoscale deployment my-app --min=2 --max=10 --cpu-percent=50

# View Horizontal Pod Autoscaler status
kubectl get hpa
```

### التحديثات والتراجع

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

## الخدمات

توفر الخدمات نقاط نهاية شبكية مستقرة لبوداتك. نظراً لأن البودات مؤقتة وتحصل على عناوين IP جديدة عند إعادة إنشائها، لا يمكنك الاعتماد على عناوين IP الخاصة بالبودات للتواصل. ينشئ Service عنوان IP افتراضي دائم واسم DNS يوجه حركة المرور إلى البودات الصحيحة، بغض النظر عن عدد النسخ الموجودة أو مكان جدولتها. هذه هي الطريقة التي تكتشف بها الخدمات بعضها البعض وتتواصل داخل عنقود Kubernetes.

### إنشاء وإدارة الخدمات

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

### DNS واكتشاف الخدمات

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

## ConfigMaps والأسرار

تخزن ConfigMaps بيانات التكوين غير الحساسة (متغيرات البيئة، ملفات التكوين)، بينما تخزن الأسرار البيانات الحساسة (كلمات المرور، مفاتيح API، شهادات TLS). كلاهما يفصل التكوين عن صور الحاويات، مما يسمح لك بتغيير الإعدادات دون إعادة بناء أو إعادة نشر تطبيقك. في بيئة الإنتاج، يجب دائماً تشفير الأسرار أثناء التخزين والتحكم في الوصول عبر RBAC.

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

### الأسرار

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

## تصحيح أخطاء العناقيد

يتطلب تصحيح أخطاء الإنتاج في Kubernetes معرفة أين تبحث. هل البودات تتعطل؟ تحقق من الأحداث والسجلات. هل الخدمة لا يمكن الوصول إليها؟ تحقق من نقاط النهاية وسياسات الشبكة. هل العقدة لا تستجيب؟ تحقق من حالة العقدة وضغط الموارد. يحتوي هذا القسم على الأوامر التي أنقذت عدداً لا يحصى من مهندسي المناوبة أثناء حوادث الإنتاج.

### أوامر التشخيص

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

### تصحيح أخطاء البودات

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

### إدارة مساحات الأسماء

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
