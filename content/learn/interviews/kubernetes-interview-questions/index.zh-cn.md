---
title: "Kubernetes (K8s) 面试准备：高级工程师问答"
description: "20道高级Kubernetes面试题，适用于高级DevOps和SRE岗位。涵盖架构、Pod生命周期、网络、存储、RBAC和生产环境故障排除。"
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) 面试准备：高级工程师问答",
    "description": "20道高级Kubernetes面试题，涵盖架构、网络、存储、安全和生产环境故障排除。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

Kubernetes是云的操作系统——也是DevOps、SRE和平台工程角色中最受欢迎的技能。高级面试会深入探讨：你将被问到控制平面内部原理、网络模型、RBAC、资源管理以及如何在压力下调试生产事故。本指南包含20道在顶级科技公司面试中反复出现的问题，附带展示Staff/Senior级别深度的答案。

**需要快速复习命令？** 在准备过程中打开我们的[Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/)。

---

## 架构

<details>
<summary><strong>1. 描述Kubernetes控制平面组件及其职责。</strong></summary>
<br>

控制平面管理集群状态：

- **kube-apiserver**：集群的入口。每个`kubectl`命令、控制器操作和调度器决策都通过API服务器。它验证并将状态持久化到etcd。
- **etcd**：分布式键值存储，保存整个集群状态（期望状态、实际状态、配置、密钥）。它是唯一的事实来源。
- **kube-scheduler**：监视没有分配节点的新创建Pod，根据资源需求、亲和性规则、污点和约束选择节点。
- **kube-controller-manager**：运行控制器循环（Deployment、ReplicaSet、Node、Job控制器），持续将期望状态与实际状态进行协调。
- **cloud-controller-manager**：与云提供商API集成，处理LoadBalancer、存储配置和节点生命周期。
</details>

<details>
<summary><strong>2. 执行`kubectl apply -f deployment.yaml`时会发生什么？</strong></summary>
<br>

1. `kubectl`将带有Deployment清单的HTTP POST/PATCH发送到**API服务器**。
2. API服务器**验证**请求（身份验证、通过RBAC授权、准入控制器）。
3. API服务器将Deployment对象写入**etcd**。
4. **Deployment控制器**检测到新的Deployment并创建**ReplicaSet**。
5. **ReplicaSet控制器**检测到它并创建指定数量的**Pod**对象。
6. **调度器**检测到未调度的Pod，根据资源可用性和约束将每个Pod分配到节点。
7. 每个分配节点上的**kubelet**检测到Pod分配，拉取容器镜像，并通过容器运行时（containerd/CRI-O）启动容器。
8. 每个节点上的**kube-proxy**在关联Service时更新iptables/IPVS规则。
</details>

<details>
<summary><strong>3. Deployment、StatefulSet和DaemonSet之间有什么区别？</strong></summary>
<br>

- **Deployment**：管理无状态应用。Pod可互换，可自由扩缩，以任意顺序创建/销毁。最适合Web服务器、API、工作节点。
- **StatefulSet**：管理有状态应用。每个Pod获得**稳定的主机名**（`pod-0`、`pod-1`）、**持久存储**（每个Pod一个PVC），且Pod按**顺序**创建/销毁。最适合数据库、Kafka、ZooKeeper。
- **DaemonSet**：确保**每个节点一个Pod**。当新节点加入集群时，Pod会自动调度到该节点。最适合日志收集器、监控代理、网络插件。
</details>

<details>
<summary><strong>4. 解释Pod的生命周期及其阶段。</strong></summary>
<br>

Pod经历以下阶段：

1. **Pending**：Pod已被接受但尚未调度或镜像正在拉取。
2. **Running**：至少一个容器正在运行或正在启动/重启。
3. **Succeeded**：所有容器以代码0退出（用于Job/批处理工作负载）。
4. **Failed**：所有容器已终止，至少一个以非零代码退出。
5. **Unknown**：节点不可达，无法确定Pod状态。

在运行中的Pod内，容器可以处于以下状态：**Waiting**（拉取镜像、init容器）、**Running**或**Terminated**（退出或崩溃）。
</details>

## 网络

<details>
<summary><strong>5. 解释Kubernetes网络模型。</strong></summary>
<br>

Kubernetes网络遵循三个基本规则：

1. **每个Pod获得自己的IP地址**——Pod之间没有NAT。
2. **所有Pod可以跨节点与所有其他Pod通信**，无需NAT。
3. **Pod看到的自身IP**与其他Pod用来访问它的IP相同。

这通过CNI（容器网络接口）插件实现，如Calico、Flannel、Cilium或Weave。它们创建满足这些规则的overlay或underlay网络。每个节点获得一个Pod CIDR子网，CNI插件处理节点间的路由。
</details>

<details>
<summary><strong>6. ClusterIP、NodePort和LoadBalancer服务之间有什么区别？</strong></summary>
<br>

- **ClusterIP**（默认）：仅内部虚拟IP。只能从集群内部访问。用于服务间通信。
- **NodePort**：在每个节点IP的静态端口（30000-32767）上暴露服务。外部流量可以访问`<NodeIP>:<NodePort>`。建立在ClusterIP之上。
- **LoadBalancer**：通过云提供商配置外部负载均衡器。获得公共IP/DNS。建立在NodePort之上。用于生产环境面向公众的服务。

还有**ExternalName**，将服务映射到DNS CNAME（无代理，仅DNS解析）。
</details>

<details>
<summary><strong>7. 什么是Ingress，它与Service有何不同？</strong></summary>
<br>

**Service**在第4层（TCP/UDP）运行——基于IP和端口将流量路由到Pod。

**Ingress**在第7层（HTTP/HTTPS）运行——基于主机名和URL路径路由流量。单个Ingress可以将`api.example.com`路由到API服务，将`app.example.com`路由到前端服务，全部通过一个负载均衡器。

Ingress需要**Ingress Controller**（nginx-ingress、Traefik、HAProxy、AWS ALB）来实际实现路由规则。Ingress资源只是配置——控制器执行实际工作。
</details>

<details>
<summary><strong>8. DNS在Kubernetes集群内部是如何工作的？</strong></summary>
<br>

Kubernetes运行**CoreDNS**（或kube-dns）作为集群附加组件。每个服务获得DNS记录：

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

当Pod对`my-service`进行DNS查询时，`/etc/resolv.conf`中的解析器（由kubelet配置）添加搜索域并查询CoreDNS。CoreDNS监视API服务器的Service/Endpoint变化并自动更新其记录。
</details>

## 存储

<details>
<summary><strong>9. 解释PersistentVolume (PV)、PersistentVolumeClaim (PVC)和StorageClass。</strong></summary>
<br>

- **PersistentVolume (PV)**：由管理员或StorageClass动态配置的存储块。独立于任何Pod存在。拥有与Pod分离的生命周期。
- **PersistentVolumeClaim (PVC)**：Pod对存储的请求。指定大小、访问模式和可选的StorageClass。Kubernetes将PVC绑定到匹配的PV。
- **StorageClass**：定义存储类别（SSD、HDD、NFS）和动态创建PV的配置器。实现按需存储配置——无需管理员干预。

流程：Pod引用PVC → PVC向StorageClass请求存储 → StorageClass触发配置器 → 配置器创建PV → PVC绑定到PV → Pod挂载PV。
</details>

<details>
<summary><strong>10. 什么是访问模式和回收策略？</strong></summary>
<br>

**访问模式**：
- **ReadWriteOnce (RWO)**：由单个节点读写挂载。最常见（AWS EBS、GCE PD）。
- **ReadOnlyMany (ROX)**：由多个节点只读挂载。用于共享配置。
- **ReadWriteMany (RWX)**：由多个节点读写挂载。需要网络存储（NFS、EFS、CephFS）。

**回收策略**（PVC被删除时的行为）：
- **Retain**：PV及其数据被保留。管理员必须手动回收。
- **Delete**：PV和底层存储被删除。动态配置的默认值。
- **Recycle**（已弃用）：对卷执行基本的`rm -rf`。请使用Retain或Delete代替。
</details>

## 安全与RBAC

<details>
<summary><strong>11. RBAC在Kubernetes中是如何工作的？</strong></summary>
<br>

RBAC（基于角色的访问控制）有四个对象：

- **Role**：在**单个命名空间**内定义对资源（Pod、服务、密钥）的权限（动词：get、list、create、delete）。
- **ClusterRole**：与Role相同但适用于**整个集群**（所有命名空间，或集群范围的资源如节点）。
- **RoleBinding**：在命名空间内将Role绑定到用户、组或服务账户。
- **ClusterRoleBinding**：在整个集群中将ClusterRole绑定到主体。

原则：从所需的最小权限开始。永远不要将`cluster-admin`绑定到应用程序服务账户。使用`kubectl auth can-i`定期审计RBAC。
</details>

<details>
<summary><strong>12. 什么是Pod Security Standards (PSS)？</strong></summary>
<br>

Pod Security Standards替代了PodSecurityPolicies（在K8s 1.25中移除）。它们定义了三个安全级别：

- **Privileged**：无限制。允许一切。用于系统级Pod（CNI插件、存储驱动程序）。
- **Baseline**：防止已知的特权提升。阻止hostNetwork、hostPID、特权容器，但允许大多数工作负载。
- **Restricted**：最高安全性。要求非root、删除所有capability、只读根文件系统、禁止特权提升。

通过命名空间级别的标签使用**Pod Security Admission**控制器执行：
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. 如何在Kubernetes中安全地管理密钥？</strong></summary>
<br>

默认的Kubernetes密钥是**base64编码的，不是加密的**。任何有API访问权限的人都可以解码它们。

加固步骤：
1. 在etcd中**启用静态加密**（使用AES-CBC或KMS提供商的`EncryptionConfiguration`）。
2. **使用外部密钥管理器**（Vault、AWS Secrets Manager）配合External Secrets Operator或CSI Secrets Store Driver。
3. **RBAC**：将密钥的`get`/`list`限制为仅需要它们的服务账户。
4. **以文件形式挂载**，而非环境变量——环境变量可能通过日志、崩溃转储和`/proc`泄露。
5. **定期轮换密钥**，尽可能使用短期凭证。
</details>

## 调度与资源

<details>
<summary><strong>14. 解释资源请求和限制。</strong></summary>
<br>

- **请求（Requests）**：**保证**给容器的CPU/内存量。调度器使用请求来决定哪个节点有足够的容量。
- **限制（Limits）**：容器可以使用的**最大**量。如果容器超过内存限制，将被OOM杀死。如果超过CPU限制，将被限流。

基于请求/限制的QoS类别：
- **Guaranteed**：所有容器的请求 == 限制。最高优先级，最后被驱逐。
- **Burstable**：请求 < 限制。中等优先级。
- **BestEffort**：未设置请求或限制。压力下首先被驱逐。

最佳实践：始终设置请求（确保调度准确性）和限制（确保集群稳定性）。
</details>

<details>
<summary><strong>15. 什么是污点（taint）、容忍（toleration）和节点亲和性（node affinity）？</strong></summary>
<br>

- **污点（Taint）**应用于节点："除非Pod能容忍此污点，否则不要在这里调度Pod。"示例：`kubectl taint nodes gpu-node gpu=true:NoSchedule`。
- **容忍（Toleration）**应用于Pod："我可以容忍此污点。"具有匹配容忍的Pod可以被调度到有污点的节点上。
- **节点亲和性（Node Affinity）**是Pod规范，表示"优先或要求调度到具有特定标签的节点。"示例：要求具有`disktype=ssd`的节点。

组合使用：给GPU节点添加污点 → 只有具有GPU容忍和GPU亲和性的Pod才能部署到那里。防止非GPU工作负载浪费昂贵的硬件。
</details>

## 故障排除

<details>
<summary><strong>16. Pod卡在CrashLoopBackOff状态。你如何调试？</strong></summary>
<br>

`CrashLoopBackOff`意味着容器持续崩溃，Kubernetes在重启前正在退避等待（指数延迟最长5分钟）。

调试步骤：
1. `kubectl describe pod <name>`——检查Events、Last State、Exit Code。
2. `kubectl logs <pod> --previous`——读取崩溃实例的日志。
3. 退出代码分析：1 = 应用错误，137 = OOM杀死，139 = 段错误，143 = SIGTERM。
4. 如果容器崩溃太快无法查看日志：`kubectl run debug --image=<image> --command -- sleep 3600`并exec进去检查环境。
5. 检查readiness/liveness探针是否配置错误（探针指向错误的端口/路径）。
6. 检查资源限制——容器可能在记录任何日志之前就被OOM杀死。
</details>

<details>
<summary><strong>17. Service没有将流量路由到Pod。你检查什么？</strong></summary>
<br>

1. **标签匹配**：Service的`spec.selector`必须与Pod的`metadata.labels`完全匹配。
2. **Endpoint存在**：`kubectl get endpoints <service>`——如果为空，选择器不匹配任何运行中的Pod。
3. **Pod处于Ready状态**：只有通过readiness探针的Pod才会出现在Endpoint中。检查`kubectl get pods`的Ready状态。
4. **端口不匹配**：Service的`targetPort`必须与容器实际监听的端口匹配。
5. **网络策略**：NetworkPolicy可能阻止了到Pod的入站流量。
6. **DNS**：从调试Pod中执行`nslookup <service-name>`验证DNS解析是否正常。
</details>

<details>
<summary><strong>18. 如何执行零停机部署？</strong></summary>
<br>

1. **滚动更新策略**（默认）：设置`maxUnavailable: 0`和`maxSurge: 1`，确保旧Pod仅在新Pod Ready之后才被移除。
2. **Readiness探针**：没有readiness探针，Kubernetes会在启动后立即认为Pod Ready——流量在应用初始化之前就到达。
3. **PreStop钩子**：添加带有短暂sleep（5-10秒）的`preStop`生命周期钩子，允许正在进行的请求在Pod从Service端点移除之前完成。
4. **PodDisruptionBudget (PDB)**：确保在自愿中断（节点排空、升级）期间始终有最少数量的Pod可用。
5. **优雅关闭**：应用程序必须处理SIGTERM并在退出前完成活动请求。
</details>

<details>
<summary><strong>19. 什么是Horizontal Pod Autoscaler，它是如何工作的？</strong></summary>
<br>

HPA根据观察到的指标（CPU、内存或自定义指标）自动缩放Pod副本数量。

工作原理：
1. HPA每15秒查询**Metrics Server**（或自定义指标API）。
2. 计算：`desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`。
3. 如果期望副本与当前不同，则更新Deployment的副本数。
4. 冷却期防止震荡：扩容稳定化（默认0秒），缩容稳定化（默认300秒）。

要求：已安装Metrics Server，容器上定义了资源请求（用于CPU/内存指标），配置了最小/最大副本边界。
</details>

<details>
<summary><strong>20. liveness探针和readiness探针有什么区别？</strong></summary>
<br>

- **Liveness探针**："容器还活着吗？"如果失败，kubelet**杀死并重启**容器。用于检测死锁或冻结的进程。
- **Readiness探针**："容器准备好处理流量了吗？"如果失败，Pod从**Service端点中移除**（不再路由流量），但容器不会重启。用于预热期、依赖检查、临时过载。

还有**Startup探针**：在应用启动之前禁用liveness/readiness探针。适用于启动缓慢的应用程序，防止过早终止。

常见错误：使用检查下游依赖（数据库）的liveness探针。如果数据库宕机，所有Pod都会重启——使故障更加严重。Liveness应该只检查应用程序本身。
</details>
