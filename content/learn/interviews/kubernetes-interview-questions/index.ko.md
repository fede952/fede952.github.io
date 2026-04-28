---
title: "Kubernetes (K8s) 면접 준비: 시니어 레벨 Q&A"
description: "시니어 DevOps 및 SRE 역할을 위한 20가지 고급 Kubernetes 면접 질문. 아키텍처, Pod 라이프사이클, 네트워킹, 스토리지, RBAC 및 프로덕션 트러블슈팅을 다룹니다."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) 면접 준비: 시니어 레벨 Q&A",
    "description": "아키텍처, 네트워킹, 스토리지, 보안 및 프로덕션 트러블슈팅을 다루는 20가지 고급 Kubernetes 면접 질문.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Kubernetes는 클라우드의 운영 체제이며, DevOps, SRE, Platform Engineering 역할에서 가장 수요가 높은 기술입니다. 시니어 레벨 면접은 깊이 있게 진행됩니다: 컨트롤 플레인 내부 구조, 네트워킹 모델, RBAC, 리소스 관리, 그리고 압박 속에서 프로덕션 인시던트를 디버깅하는 방법에 대해 질문받게 됩니다. 이 가이드에는 주요 기술 회사 면접에서 반복적으로 등장하는 20가지 질문이 포함되어 있으며, Staff/Senior 레벨에서 기대되는 깊이를 보여주는 답변이 함께 제공됩니다.

**빠른 명령어 복습이 필요하신가요?** 준비하는 동안 [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/)를 열어두세요.

---

## 아키텍처

<details>
<summary><strong>1. Kubernetes 컨트롤 플레인 구성 요소와 각각의 역할을 설명하세요.</strong></summary>
<br>

컨트롤 플레인은 클러스터 상태를 관리합니다:

- **kube-apiserver**: 클러스터의 정문입니다. 모든 `kubectl` 명령, 컨트롤러 동작, 스케줄러 결정이 API 서버를 통과합니다. 상태를 검증하고 etcd에 영속화합니다.
- **etcd**: 전체 클러스터 상태(원하는 상태, 실제 상태, 설정, 시크릿)를 보관하는 분산 키-값 저장소입니다. 유일한 진실의 원천입니다.
- **kube-scheduler**: 노드가 할당되지 않은 새로 생성된 Pod를 감시하고 리소스 요구 사항, 어피니티 규칙, taint, 제약 조건에 따라 노드를 선택합니다.
- **kube-controller-manager**: 컨트롤러 루프(Deployment, ReplicaSet, Node, Job 컨트롤러)를 실행하여 원하는 상태와 실제 상태를 지속적으로 조정합니다.
- **cloud-controller-manager**: 클라우드 프로바이더 API와 통합하여 LoadBalancer, 스토리지 프로비저닝, 노드 라이프사이클을 처리합니다.
</details>

<details>
<summary><strong>2. `kubectl apply -f deployment.yaml`을 실행하면 무슨 일이 일어나나요?</strong></summary>
<br>

1. `kubectl`이 Deployment 매니페스트와 함께 HTTP POST/PATCH를 **API 서버**로 전송합니다.
2. API 서버가 요청을 **검증**합니다(인증, RBAC를 통한 인가, 어드미션 컨트롤러).
3. API 서버가 Deployment 객체를 **etcd**에 기록합니다.
4. **Deployment 컨트롤러**가 새 Deployment를 감지하고 **ReplicaSet**을 생성합니다.
5. **ReplicaSet 컨트롤러**가 이를 감지하고 지정된 수의 **Pod** 객체를 생성합니다.
6. **스케줄러**가 미스케줄된 Pod를 감지하고 리소스 가용성과 제약 조건에 따라 각각을 노드에 할당합니다.
7. 할당된 각 노드의 **kubelet**이 Pod 할당을 감지하고 컨테이너 이미지를 풀한 다음 컨테이너 런타임(containerd/CRI-O)을 통해 컨테이너를 시작합니다.
8. 각 노드의 **kube-proxy**가 Service가 연결된 경우 iptables/IPVS 규칙을 업데이트합니다.
</details>

<details>
<summary><strong>3. Deployment, StatefulSet, DaemonSet의 차이점은 무엇인가요?</strong></summary>
<br>

- **Deployment**: 스테이트리스 애플리케이션을 관리합니다. Pod는 상호 교환 가능하고, 자유롭게 스케일링할 수 있으며, 어떤 순서로든 생성/삭제됩니다. 웹 서버, API, 워커에 적합합니다.
- **StatefulSet**: 스테이트풀 애플리케이션을 관리합니다. 각 Pod는 **안정적인 호스트 이름**(`pod-0`, `pod-1`), **영구 스토리지**(Pod별 PVC)를 받으며, Pod는 **순서대로** 생성/삭제됩니다. 데이터베이스, Kafka, ZooKeeper에 적합합니다.
- **DaemonSet**: **노드당 하나의 Pod**를 보장합니다. 새 노드가 클러스터에 합류하면 자동으로 Pod가 스케줄됩니다. 로그 수집기, 모니터링 에이전트, 네트워크 플러그인에 적합합니다.
</details>

<details>
<summary><strong>4. Pod 라이프사이클과 각 단계를 설명하세요.</strong></summary>
<br>

Pod는 다음 단계를 거칩니다:

1. **Pending**: Pod가 수락되었지만 아직 스케줄되지 않았거나 이미지가 풀되고 있는 상태.
2. **Running**: 최소 하나의 컨테이너가 실행 중이거나 시작/재시작 중.
3. **Succeeded**: 모든 컨테이너가 코드 0으로 종료(Jobs/배치 워크로드용).
4. **Failed**: 모든 컨테이너가 종료되었고, 최소 하나가 0이 아닌 코드로 종료.
5. **Unknown**: 노드에 연결할 수 없어 Pod 상태를 확인할 수 없음.

실행 중인 Pod 내에서 컨테이너는 다음 상태에 있을 수 있습니다: **Waiting**(이미지 풀 중, init 컨테이너), **Running**, 또는 **Terminated**(종료 또는 크래시).
</details>

## 네트워킹

<details>
<summary><strong>5. Kubernetes 네트워킹 모델을 설명하세요.</strong></summary>
<br>

Kubernetes 네트워킹은 세 가지 기본 규칙을 따릅니다:

1. **모든 Pod는 자체 IP 주소를 받음** — Pod 간 NAT 없음.
2. **모든 Pod는 NAT 없이 노드 간 다른 모든 Pod와 통신 가능**.
3. **Pod가 자신에게 보이는 IP**는 다른 Pod가 해당 Pod에 도달하는 데 사용하는 IP와 동일.

이는 Calico, Flannel, Cilium, Weave 같은 CNI(Container Network Interface) 플러그인으로 구현됩니다. 이러한 규칙을 충족하는 오버레이 또는 언더레이 네트워크를 생성합니다. 각 노드는 Pod CIDR 서브넷을 받고, CNI 플러그인이 노드 간 라우팅을 처리합니다.
</details>

<details>
<summary><strong>6. ClusterIP, NodePort, LoadBalancer 서비스의 차이점은 무엇인가요?</strong></summary>
<br>

- **ClusterIP**(기본값): 내부 전용 가상 IP. 클러스터 내부에서만 접근 가능. 서비스 간 통신에 사용.
- **NodePort**: 모든 노드 IP의 정적 포트(30000-32767)에 서비스를 노출. 외부 트래픽이 `<NodeIP>:<NodePort>`에 도달 가능. ClusterIP 위에 구축.
- **LoadBalancer**: 클라우드 프로바이더를 통해 외부 로드 밸런서를 프로비저닝. 퍼블릭 IP/DNS를 획득. NodePort 위에 구축. 프로덕션 퍼블릭 서비스에 사용.

또한 **ExternalName**이 있으며, 서비스를 DNS CNAME에 매핑합니다(프록싱 없이 DNS 해석만).
</details>

<details>
<summary><strong>7. Ingress란 무엇이며 Service와 어떻게 다른가요?</strong></summary>
<br>

**Service**는 레이어 4(TCP/UDP)에서 동작하며, IP와 포트를 기반으로 Pod에 트래픽을 라우팅합니다.

**Ingress**는 레이어 7(HTTP/HTTPS)에서 동작하며, 호스트 이름과 URL 경로를 기반으로 트래픽을 라우팅합니다. 단일 Ingress로 `api.example.com`을 API 서비스로, `app.example.com`을 프런트엔드 서비스로, 모두 하나의 로드 밸런서를 통해 라우팅할 수 있습니다.

Ingress는 라우팅 규칙을 실제로 구현하는 **Ingress Controller**(nginx-ingress, Traefik, HAProxy, AWS ALB)가 필요합니다. Ingress 리소스는 설정일 뿐이며, 컨트롤러가 실제 작업을 수행합니다.
</details>

<details>
<summary><strong>8. Kubernetes 클러스터 내부에서 DNS는 어떻게 작동하나요?</strong></summary>
<br>

Kubernetes는 클러스터 애드온으로 **CoreDNS**(또는 kube-dns)를 실행합니다. 각 서비스는 DNS 레코드를 받습니다:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Pod가 `my-service`에 대한 DNS 쿼리를 하면, `/etc/resolv.conf`의 리졸버(kubelet이 설정)가 검색 도메인을 추가하고 CoreDNS에 쿼리합니다. CoreDNS는 API 서버의 Service/Endpoint 변경 사항을 감시하고 레코드를 자동으로 업데이트합니다.
</details>

## 스토리지

<details>
<summary><strong>9. PersistentVolume (PV), PersistentVolumeClaim (PVC), StorageClass를 설명하세요.</strong></summary>
<br>

- **PersistentVolume (PV)**: 관리자가 프로비저닝하거나 StorageClass에 의해 동적으로 프로비저닝된 스토리지 조각. Pod와 독립적으로 존재하며, Pod와 별도의 라이프사이클을 가집니다.
- **PersistentVolumeClaim (PVC)**: Pod의 스토리지 요청. 크기, 접근 모드, 선택적으로 StorageClass를 지정합니다. Kubernetes가 PVC를 일치하는 PV에 바인딩합니다.
- **StorageClass**: 스토리지 클래스(SSD, HDD, NFS)와 PV를 동적으로 생성하는 프로비저너를 정의합니다. 온디맨드 스토리지 프로비저닝을 가능하게 하며, 관리자 개입이 필요 없습니다.

흐름: Pod가 PVC 참조 → PVC가 StorageClass에 스토리지 요청 → StorageClass가 프로비저너 트리거 → 프로비저너가 PV 생성 → PVC가 PV에 바인딩 → Pod가 PV 마운트.
</details>

<details>
<summary><strong>10. 접근 모드와 리클레임 정책이란 무엇인가요?</strong></summary>
<br>

**접근 모드**:
- **ReadWriteOnce (RWO)**: 단일 노드에서 읽기/쓰기 마운트. 가장 일반적(AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)**: 많은 노드에서 읽기 전용 마운트. 공유 설정에 사용.
- **ReadWriteMany (RWX)**: 많은 노드에서 읽기/쓰기 마운트. 네트워크 스토리지 필요(NFS, EFS, CephFS).

**리클레임 정책**(PVC 삭제 시 동작):
- **Retain**: PV가 데이터와 함께 유지. 관리자가 수동으로 회수해야 함.
- **Delete**: PV와 기반 스토리지가 삭제됨. 동적 프로비저닝의 기본값.
- **Recycle**(사용 중단): 볼륨에 대한 기본 `rm -rf`. 대신 Retain 또는 Delete를 사용.
</details>

## 보안 및 RBAC

<details>
<summary><strong>11. Kubernetes에서 RBAC는 어떻게 작동하나요?</strong></summary>
<br>

RBAC(역할 기반 접근 제어)에는 네 가지 객체가 있습니다:

- **Role**: **단일 네임스페이스** 내의 리소스(Pod, 서비스, 시크릿)에 대한 권한(동사: get, list, create, delete)을 정의.
- **ClusterRole**: Role과 동일하지만 **클러스터 전체**(모든 네임스페이스 또는 노드 같은 클러스터 범위 리소스).
- **RoleBinding**: 네임스페이스 내에서 Role을 사용자, 그룹 또는 서비스 계정에 바인딩.
- **ClusterRoleBinding**: 전체 클러스터에 걸쳐 ClusterRole을 주체에 바인딩.

원칙: 필요한 최소 권한으로 시작하세요. 애플리케이션 서비스 계정에 `cluster-admin`을 바인딩하지 마세요. `kubectl auth can-i`로 정기적으로 RBAC를 감사하세요.
</details>

<details>
<summary><strong>12. Pod Security Standards (PSS)란 무엇인가요?</strong></summary>
<br>

Pod Security Standards는 PodSecurityPolicies(K8s 1.25에서 제거됨)를 대체했습니다. 세 가지 보안 수준을 정의합니다:

- **Privileged**: 제한 없음. 모든 것을 허용. 시스템 레벨 Pod(CNI 플러그인, 스토리지 드라이버)에 사용.
- **Baseline**: 알려진 권한 상승을 방지. hostNetwork, hostPID, 특권 컨테이너를 차단하지만 대부분의 워크로드를 허용.
- **Restricted**: 최대 보안. non-root 필수, 모든 capability 삭제, 읽기 전용 루트 파일시스템, 권한 상승 불가.

네임스페이스 레벨에서 레이블을 사용하여 **Pod Security Admission** 컨트롤러로 적용:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. Kubernetes에서 시크릿을 안전하게 관리하는 방법은?</strong></summary>
<br>

기본 Kubernetes 시크릿은 **base64로 인코딩되어 있을 뿐, 암호화되지 않았습니다**. API 접근 권한이 있는 누구나 디코딩할 수 있습니다.

강화 단계:
1. etcd에서 **저장 시 암호화 활성화**(`EncryptionConfiguration`에 AES-CBC 또는 KMS 프로바이더 사용).
2. External Secrets Operator 또는 CSI Secrets Store Driver와 함께 **외부 시크릿 관리자 사용**(Vault, AWS Secrets Manager).
3. **RBAC**: 시크릿에 대한 `get`/`list`를 필요한 서비스 계정으로만 제한.
4. 환경 변수가 아닌 **파일로 마운트** — 환경 변수는 로그, 크래시 덤프, `/proc`를 통해 유출될 수 있습니다.
5. **시크릿을 정기적으로 로테이션**하고 가능한 경우 단기 자격 증명을 사용.
</details>

## 스케줄링 및 리소스

<details>
<summary><strong>14. 리소스 요청과 제한을 설명하세요.</strong></summary>
<br>

- **요청(Requests)**: 컨테이너에 **보장**되는 CPU/메모리 양. 스케줄러가 어떤 노드에 충분한 용량이 있는지 결정하는 데 요청을 사용합니다.
- **제한(Limits)**: 컨테이너가 사용할 수 있는 **최대** 양. 컨테이너가 메모리 제한을 초과하면 OOM 킬됩니다. CPU 제한을 초과하면 스로틀링됩니다.

요청/제한 기반 QoS 클래스:
- **Guaranteed**: 모든 컨테이너에서 요청 == 제한. 최고 우선순위, 마지막으로 퇴거.
- **Burstable**: 요청 < 제한. 중간 우선순위.
- **BestEffort**: 요청이나 제한이 설정되지 않음. 압박 시 첫 번째로 퇴거.

모범 사례: 항상 요청(스케줄링 정확도를 위해)과 제한(클러스터 안정성을 위해)을 설정하세요.
</details>

<details>
<summary><strong>15. taint, toleration, node affinity란 무엇인가요?</strong></summary>
<br>

- **Taint**는 노드에 적용됩니다: "이 taint를 toleration하지 않는 한 여기에 Pod를 스케줄하지 마세요." 예시: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Toleration**은 Pod에 적용됩니다: "이 taint를 toleration할 수 있습니다." 일치하는 toleration이 있는 Pod는 taint된 노드에 스케줄될 수 있습니다.
- **Node Affinity**는 Pod 스펙으로 "특정 레이블이 있는 노드에 스케줄링을 선호하거나 요구합니다"라고 말합니다. 예시: `disktype=ssd` 노드를 요구.

함께 사용: GPU 노드에 taint 적용 → GPU toleration과 GPU affinity가 있는 Pod만 배치됨. 비GPU 워크로드가 비싼 하드웨어를 낭비하는 것을 방지.
</details>

## 트러블슈팅

<details>
<summary><strong>16. Pod가 CrashLoopBackOff 상태에 머물러 있습니다. 어떻게 디버깅하나요?</strong></summary>
<br>

`CrashLoopBackOff`는 컨테이너가 계속 크래시하고 Kubernetes가 재시작 전에 대기하고 있음을 의미합니다(최대 5분까지 지수 백오프).

디버깅 단계:
1. `kubectl describe pod <name>` — Events, Last State, Exit Code를 확인.
2. `kubectl logs <pod> --previous` — 크래시된 인스턴스의 로그를 읽음.
3. 종료 코드 분석: 1 = 앱 오류, 137 = OOM 킬, 139 = 세그폴트, 143 = SIGTERM.
4. 컨테이너가 로그를 남기기 전에 크래시하는 경우: `kubectl run debug --image=<image> --command -- sleep 3600`으로 exec하여 환경을 검사.
5. readiness/liveness 프로브가 잘못 설정되었는지 확인(프로브가 잘못된 포트/경로를 사용).
6. 리소스 제한 확인 — 컨테이너가 무엇이든 로그하기 전에 OOM 킬될 수 있음.
</details>

<details>
<summary><strong>17. Service가 Pod로 트래픽을 라우팅하지 않습니다. 무엇을 확인하나요?</strong></summary>
<br>

1. **레이블 일치**: Service의 `spec.selector`가 Pod의 `metadata.labels`와 정확히 일치해야 합니다.
2. **Endpoint 존재**: `kubectl get endpoints <service>` — 비어 있으면 셀렉터가 실행 중인 Pod와 일치하지 않습니다.
3. **Pod가 Ready**: readiness 프로브를 통과한 Pod만 Endpoint에 나타납니다. `kubectl get pods`에서 Ready 상태를 확인.
4. **포트 불일치**: Service의 `targetPort`가 컨테이너가 실제로 리스닝하는 포트와 일치해야 합니다.
5. **Network Policy**: NetworkPolicy가 Pod로의 인그레스를 차단하고 있을 수 있습니다.
6. **DNS**: 디버그 Pod에서 `nslookup <service-name>`으로 DNS 해석이 작동하는지 확인.
</details>

<details>
<summary><strong>18. 무중단 배포는 어떻게 수행하나요?</strong></summary>
<br>

1. **롤링 업데이트 전략**(기본값): `maxUnavailable: 0`과 `maxSurge: 1`을 설정하여 새 Pod가 Ready된 후에만 이전 Pod가 제거되도록 보장.
2. **Readiness 프로브**: readiness 프로브가 없으면 Kubernetes는 시작 직후 Pod를 Ready로 간주 — 앱이 초기화되기 전에 트래픽이 도달합니다.
3. **PreStop 훅**: 짧은 sleep(5-10초)이 포함된 `preStop` 라이프사이클 훅을 추가하여 Pod가 Service 엔드포인트에서 제거되기 전에 진행 중인 요청이 완료되도록 합니다.
4. **PodDisruptionBudget (PDB)**: 자발적 중단(노드 드레인, 업그레이드) 중 최소 수의 Pod가 항상 사용 가능하도록 보장.
5. **그레이스풀 셧다운**: 애플리케이션이 SIGTERM을 처리하고 종료 전에 활성 요청을 완료해야 합니다.
</details>

<details>
<summary><strong>19. Horizontal Pod Autoscaler란 무엇이며 어떻게 작동하나요?</strong></summary>
<br>

HPA는 관찰된 메트릭(CPU, 메모리 또는 커스텀 메트릭)에 기반하여 Pod 레플리카 수를 자동으로 스케일링합니다.

작동 방식:
1. HPA가 15초마다 **Metrics Server**(또는 커스텀 메트릭 API)를 쿼리합니다.
2. 계산: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. 원하는 레플리카가 현재와 다르면 Deployment의 레플리카 수를 업데이트합니다.
4. 쿨다운 기간이 불안정한 변동을 방지: 스케일업 안정화(기본 0초), 스케일다운 안정화(기본 300초).

요구 사항: Metrics Server 설치, 컨테이너에 리소스 요청 정의(CPU/메모리 메트릭용), 최소/최대 레플리카 경계 설정.
</details>

<details>
<summary><strong>20. liveness 프로브와 readiness 프로브의 차이점은 무엇인가요?</strong></summary>
<br>

- **Liveness 프로브**: "컨테이너가 살아있나요?" 실패하면 kubelet이 컨테이너를 **킬하고 재시작**합니다. 데드락이나 프리즈된 프로세스 감지에 사용.
- **Readiness 프로브**: "컨테이너가 트래픽을 처리할 준비가 되었나요?" 실패하면 Pod가 **Service 엔드포인트에서 제거**되지만(트래픽이 라우팅되지 않음), 컨테이너는 재시작되지 않습니다. 워밍업 기간, 종속성 확인, 일시적 과부하에 사용.

또한 **Startup 프로브**가 있습니다: 앱이 시작될 때까지 liveness/readiness 프로브를 비활성화합니다. 느리게 시작하는 애플리케이션의 조기 킬을 방지하는 데 유용합니다.

흔한 실수: 다운스트림 종속성(데이터베이스)을 확인하는 liveness 프로브 사용. 데이터베이스가 다운되면 모든 Pod가 재시작되어 장애가 악화됩니다. Liveness는 애플리케이션 자체만 확인해야 합니다.
</details>
