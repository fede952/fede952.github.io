---
title: "Kubernetes (K8s) 面接対策：シニアレベルQ&A"
description: "シニアDevOpsおよびSREロール向けの20の高度なKubernetes面接質問。アーキテクチャ、Podライフサイクル、ネットワーキング、ストレージ、RBAC、本番環境のトラブルシューティングをカバー。"
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) 面接対策：シニアレベルQ&A",
    "description": "アーキテクチャ、ネットワーキング、ストレージ、セキュリティ、本番環境のトラブルシューティングをカバーする20の高度なKubernetes面接質問。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ja"
  }
---

## システム初期化

Kubernetesはクラウドのオペレーティングシステムであり、DevOps、SRE、Platform Engineeringの役割で最も需要の高いスキルです。シニアレベルの面接は深い内容に踏み込みます：コントロールプレーンの内部構造、ネットワーキングモデル、RBAC、リソース管理、プレッシャー下での本番インシデントのデバッグ方法について質問されます。このガイドには、トップテック企業の面接で繰り返し出題される20の質問が含まれており、Staff/Seniorレベルで期待される深さを示す回答が付いています。

**コマンドの簡単な復習が必要ですか？** 準備中は[Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/)を開いておきましょう。

---

## アーキテクチャ

<details>
<summary><strong>1. Kubernetesのコントロールプレーンコンポーネントとその責務を説明してください。</strong></summary>
<br>

コントロールプレーンはクラスターの状態を管理します：

- **kube-apiserver**：クラスターの玄関口。すべての`kubectl`コマンド、コントローラーアクション、スケジューラーの決定はAPIサーバーを通過します。状態を検証し、etcdに永続化します。
- **etcd**：クラスターの全状態（望ましい状態、実際の状態、設定、シークレット）を保持する分散キーバリューストア。唯一の真実の源です。
- **kube-scheduler**：ノードが割り当てられていない新しく作成されたPodを監視し、リソース要件、アフィニティルール、taint、制約に基づいてノードを選択します。
- **kube-controller-manager**：コントローラーループ（Deployment、ReplicaSet、Node、Jobコントローラー）を実行し、望ましい状態と実際の状態を継続的に調整します。
- **cloud-controller-manager**：クラウドプロバイダーAPIと統合し、LoadBalancer、ストレージプロビジョニング、ノードライフサイクルを処理します。
</details>

<details>
<summary><strong>2. `kubectl apply -f deployment.yaml`を実行すると何が起こりますか？</strong></summary>
<br>

1. `kubectl`がDeploymentマニフェストを含むHTTP POST/PATCHを**APIサーバー**に送信します。
2. APIサーバーがリクエストを**検証**します（認証、RBACによる認可、アドミッションコントローラー）。
3. APIサーバーがDeploymentオブジェクトを**etcd**に書き込みます。
4. **Deploymentコントローラー**が新しいDeploymentを検出し、**ReplicaSet**を作成します。
5. **ReplicaSetコントローラー**がそれを検出し、指定された数の**Pod**オブジェクトを作成します。
6. **スケジューラー**が未スケジュールのPodを検出し、リソースの可用性と制約に基づいて各Podをノードに割り当てます。
7. 割り当てられた各ノードの**kubelet**がPodの割り当てを検出し、コンテナイメージをプルし、コンテナランタイム（containerd/CRI-O）を介してコンテナを起動します。
8. 各ノードの**kube-proxy**が、Serviceが関連付けられている場合にiptables/IPVSルールを更新します。
</details>

<details>
<summary><strong>3. Deployment、StatefulSet、DaemonSetの違いは何ですか？</strong></summary>
<br>

- **Deployment**：ステートレスアプリケーションを管理します。Podは交換可能で、自由にスケールでき、任意の順序で作成/破棄されます。Webサーバー、API、ワーカーに最適です。
- **StatefulSet**：ステートフルアプリケーションを管理します。各Podは**安定したホスト名**（`pod-0`、`pod-1`）、**永続ストレージ**（Pod毎のPVC）を取得し、Podは**順序通り**に作成/破棄されます。データベース、Kafka、ZooKeeperに最適です。
- **DaemonSet**：**ノードごとに1つのPod**を保証します。新しいノードがクラスターに参加すると、Podが自動的にスケジュールされます。ログコレクター、モニタリングエージェント、ネットワークプラグインに最適です。
</details>

<details>
<summary><strong>4. Podのライフサイクルとそのフェーズを説明してください。</strong></summary>
<br>

Podは以下のフェーズを経ます：

1. **Pending**：Podは受け入れられたが、まだスケジュールされていないか、イメージがプルされている状態。
2. **Running**：少なくとも1つのコンテナが実行中、または起動/再起動中。
3. **Succeeded**：すべてのコンテナがコード0で終了（Jobs/バッチワークロード向け）。
4. **Failed**：すべてのコンテナが終了し、少なくとも1つがゼロ以外のコードで終了。
5. **Unknown**：ノードに到達できず、Podの状態を判定できない。

実行中のPod内で、コンテナは以下の状態になりえます：**Waiting**（イメージプル中、initコンテナ）、**Running**、または**Terminated**（終了またはクラッシュ）。
</details>

## ネットワーキング

<details>
<summary><strong>5. Kubernetesのネットワーキングモデルを説明してください。</strong></summary>
<br>

Kubernetesのネットワーキングは3つの基本ルールに従います：

1. **すべてのPodは独自のIPアドレスを取得** — Pod間でNATなし。
2. **すべてのPodはノードを超えて他のすべてのPodと通信可能** — NATなし。
3. **Podが自身に対して見るIP**は、他のPodがそれに到達するために使用するIPと同じ。

これはCalico、Flannel、Cilium、WeaveなどのCNI（Container Network Interface）プラグインによって実装されます。オーバーレイまたはアンダーレイネットワークを作成し、これらのルールを満たします。各ノードはPod CIDRサブネットを取得し、CNIプラグインがノード間のルーティングを処理します。
</details>

<details>
<summary><strong>6. ClusterIP、NodePort、LoadBalancerサービスの違いは何ですか？</strong></summary>
<br>

- **ClusterIP**（デフォルト）：内部専用の仮想IP。クラスター内からのみアクセス可能。サービス間通信に使用。
- **NodePort**：各ノードのIPの静的ポート（30000-32767）でサービスを公開。外部トラフィックは`<NodeIP>:<NodePort>`に到達可能。ClusterIPの上に構築。
- **LoadBalancer**：クラウドプロバイダー経由で外部ロードバランサーをプロビジョニング。パブリックIP/DNSを取得。NodePortの上に構築。本番の公開サービスに使用。

また**ExternalName**があり、サービスをDNS CNAMEにマッピングします（プロキシなし、DNS解決のみ）。
</details>

<details>
<summary><strong>7. Ingressとは何で、Serviceとどう異なりますか？</strong></summary>
<br>

**Service**はレイヤー4（TCP/UDP）で動作し、IPとポートに基づいてトラフィックをPodにルーティングします。

**Ingress**はレイヤー7（HTTP/HTTPS）で動作し、ホスト名とURLパスに基づいてトラフィックをルーティングします。単一のIngressで`api.example.com`をAPIサービスに、`app.example.com`をフロントエンドサービスに、すべて1つのロードバランサーを通じてルーティングできます。

Ingressにはルーティングルールを実際に実装する**Ingress Controller**（nginx-ingress、Traefik、HAProxy、AWS ALB）が必要です。Ingressリソースは設定にすぎず、コントローラーが実際の作業を行います。
</details>

<details>
<summary><strong>8. Kubernetesクラスター内でDNSはどのように機能しますか？</strong></summary>
<br>

Kubernetesはクラスターアドオンとして**CoreDNS**（またはkube-dns）を実行します。各サービスはDNSレコードを取得します：

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Podが`my-service`のDNSクエリを行うと、`/etc/resolv.conf`のリゾルバー（kubeletによって設定）が検索ドメインを追加してCoreDNSにクエリします。CoreDNSはAPIサーバーのService/Endpointの変更を監視し、レコードを自動的に更新します。
</details>

## ストレージ

<details>
<summary><strong>9. PersistentVolume (PV)、PersistentVolumeClaim (PVC)、StorageClassを説明してください。</strong></summary>
<br>

- **PersistentVolume (PV)**：管理者またはStorageClassによって動的にプロビジョニングされたストレージの一部。Podとは独立して存在し、Podとは別のライフサイクルを持ちます。
- **PersistentVolumeClaim (PVC)**：Podからのストレージリクエスト。サイズ、アクセスモード、オプションでStorageClassを指定します。Kubernetesが一致するPVにPVCをバインドします。
- **StorageClass**：ストレージのクラス（SSD、HDD、NFS）とPVを動的に作成するプロビジョナーを定義します。オンデマンドのストレージプロビジョニングを可能にし、管理者の介入は不要です。

フロー：PodがPVCを参照 → PVCがStorageClassにストレージを要求 → StorageClassがプロビジョナーをトリガー → プロビジョナーがPVを作成 → PVCがPVにバインド → PodがPVをマウント。
</details>

<details>
<summary><strong>10. アクセスモードとリクレームポリシーとは何ですか？</strong></summary>
<br>

**アクセスモード**：
- **ReadWriteOnce (RWO)**：単一ノードで読み書きマウント。最も一般的（AWS EBS、GCE PD）。
- **ReadOnlyMany (ROX)**：多くのノードで読み取り専用マウント。共有設定に使用。
- **ReadWriteMany (RWX)**：多くのノードで読み書きマウント。ネットワークストレージが必要（NFS、EFS、CephFS）。

**リクレームポリシー**（PVCが削除されたときの動作）：
- **Retain**：PVはデータとともに保持。管理者が手動で回収する必要あり。
- **Delete**：PVと基盤ストレージが削除。動的プロビジョニングのデフォルト。
- **Recycle**（非推奨）：ボリュームに対する基本的な`rm -rf`。代わりにRetainまたはDeleteを使用。
</details>

## セキュリティとRBAC

<details>
<summary><strong>11. KubernetesでRBACはどのように機能しますか？</strong></summary>
<br>

RBAC（ロールベースアクセス制御）には4つのオブジェクトがあります：

- **Role**：**単一のnamespace**内のリソース（Pod、サービス、シークレット）に対する権限（動詞：get、list、create、delete）を定義。
- **ClusterRole**：Roleと同じだが**クラスター全体**（すべてのnamespace、またはノードなどのクラスタースコープリソース）。
- **RoleBinding**：namespace内でRoleをユーザー、グループ、またはサービスアカウントにバインド。
- **ClusterRoleBinding**：クラスター全体でClusterRoleをサブジェクトにバインド。

原則：必要最小限の権限から始めること。アプリケーションのサービスアカウントに`cluster-admin`をバインドしないこと。`kubectl auth can-i`で定期的にRBACを監査すること。
</details>

<details>
<summary><strong>12. Pod Security Standards (PSS)とは何ですか？</strong></summary>
<br>

Pod Security StandardsはPodSecurityPolicies（K8s 1.25で削除）を置き換えました。3つのセキュリティレベルを定義します：

- **Privileged**：制限なし。すべてを許可。システムレベルのPod（CNIプラグイン、ストレージドライバー）に使用。
- **Baseline**：既知の特権昇格を防止。hostNetwork、hostPID、特権コンテナをブロックするが、ほとんどのワークロードを許可。
- **Restricted**：最大のセキュリティ。non-root、すべてのcapabilityの削除、読み取り専用ルートファイルシステム、特権昇格なしを要求。

namespaceレベルでラベルを使用して**Pod Security Admission**コントローラーで適用：
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. Kubernetesでシークレットを安全に管理するにはどうしますか？</strong></summary>
<br>

デフォルトのKubernetesシークレットは**base64エンコードであり、暗号化されていません**。APIアクセスを持つ人は誰でもデコードできます。

強化手順：
1. etcdで**保存時の暗号化を有効化**（AES-CBCまたはKMSプロバイダーを使用した`EncryptionConfiguration`）。
2. External Secrets OperatorまたはCSI Secrets Store Driverで**外部シークレットマネージャーを使用**（Vault、AWS Secrets Manager）。
3. **RBAC**：シークレットに対する`get`/`list`を必要なサービスアカウントのみに制限。
4. 環境変数ではなく**ファイルとしてマウント** — 環境変数はログ、クラッシュダンプ、`/proc`を通じて漏洩する可能性があります。
5. **シークレットを定期的にローテーション**し、可能な場合は短命の認証情報を使用。
</details>

## スケジューリングとリソース

<details>
<summary><strong>14. リソースリクエストとリミットを説明してください。</strong></summary>
<br>

- **リクエスト（Requests）**：コンテナに**保証**されるCPU/メモリの量。スケジューラーはリクエストを使用してどのノードに十分な容量があるかを判断します。
- **リミット（Limits）**：コンテナが使用できる**最大**量。コンテナがメモリリミットを超えるとOOMキルされます。CPUリミットを超えるとスロットリングされます。

リクエスト/リミットに基づくQoSクラス：
- **Guaranteed**：すべてのコンテナでリクエスト == リミット。最高優先度、最後に退去。
- **Burstable**：リクエスト < リミット。中程度の優先度。
- **BestEffort**：リクエストもリミットも設定なし。圧力下で最初に退去。

ベストプラクティス：常にリクエスト（スケジューリングの精度のため）とリミット（クラスターの安定性のため）を設定すること。
</details>

<details>
<summary><strong>15. taint、toleration、node affinityとは何ですか？</strong></summary>
<br>

- **Taint**はノードに適用：「このtaintをtolerationしない限り、ここにPodをスケジュールしない」。例：`kubectl taint nodes gpu-node gpu=true:NoSchedule`。
- **Toleration**はPodに適用：「このtaintをtolerationできる」。一致するtolerationを持つPodはtaintされたノードにスケジュール可能。
- **Node Affinity**はPodの仕様で、「特定のラベルを持つノードでのスケジューリングを優先または要求する」。例：`disktype=ssd`のノードを要求。

組み合わせて使用：GPUノードにtaintを適用 → GPU tolerationとGPU affinityを持つPodだけがそこに配置。非GPUワークロードが高価なハードウェアを無駄にするのを防止。
</details>

## トラブルシューティング

<details>
<summary><strong>16. PodがCrashLoopBackOffで停止しています。どのようにデバッグしますか？</strong></summary>
<br>

`CrashLoopBackOff`はコンテナがクラッシュし続け、Kubernetesが再起動前に待機していることを意味します（最大5分の指数バックオフ）。

デバッグ手順：
1. `kubectl describe pod <name>` — Events、Last State、Exit Codeを確認。
2. `kubectl logs <pod> --previous` — クラッシュしたインスタンスのログを読む。
3. 終了コード分析：1 = アプリエラー、137 = OOMキル、139 = セグフォルト、143 = SIGTERM。
4. コンテナがログを出す前にクラッシュする場合：`kubectl run debug --image=<image> --command -- sleep 3600`でexecして環境を調査。
5. readiness/livenessプローブの設定ミスをチェック（間違ったポート/パスへのプローブ）。
6. リソースリミットをチェック — コンテナが何もログに記録する前にOOMキルされている可能性。
</details>

<details>
<summary><strong>17. ServiceがPodにトラフィックをルーティングしていません。何を確認しますか？</strong></summary>
<br>

1. **ラベルが一致**：Serviceの`spec.selector`がPodの`metadata.labels`と正確に一致する必要があります。
2. **Endpointが存在**：`kubectl get endpoints <service>` — 空の場合、セレクターが実行中のPodと一致していません。
3. **PodがReady**：readinessプローブを通過したPodのみがEndpointに表示されます。`kubectl get pods`でReadyステータスを確認。
4. **ポートの不一致**：Serviceの`targetPort`がコンテナが実際にリッスンしているポートと一致する必要があります。
5. **Network Policy**：NetworkPolicyがPodへのingressをブロックしている可能性。
6. **DNS**：デバッグPodから`nslookup <service-name>`でDNS解決が機能することを確認。
</details>

<details>
<summary><strong>18. ゼロダウンタイムデプロイメントをどのように実行しますか？</strong></summary>
<br>

1. **ローリングアップデート戦略**（デフォルト）：`maxUnavailable: 0`と`maxSurge: 1`を設定し、新しいPodがReadyになった後にのみ古いPodが削除されるようにします。
2. **Readinessプローブ**：readinessプローブがないと、Kubernetesは起動直後にPodをReadyとみなし、アプリが初期化される前にトラフィックが到達します。
3. **PreStopフック**：短いsleep（5-10秒）を含む`preStop`ライフサイクルフックを追加し、PodがServiceエンドポイントから削除される前に進行中のリクエストが完了できるようにします。
4. **PodDisruptionBudget (PDB)**：自発的な中断（ノードドレイン、アップグレード）中に最小数のPodが常に利用可能であることを保証します。
5. **グレースフルシャットダウン**：アプリケーションはSIGTERMを処理し、終了前にアクティブなリクエストを完了する必要があります。
</details>

<details>
<summary><strong>19. Horizontal Pod Autoscalerとは何で、どのように機能しますか？</strong></summary>
<br>

HPAは観測されたメトリクス（CPU、メモリ、またはカスタムメトリクス）に基づいてPodレプリカの数を自動的にスケーリングします。

仕組み：
1. HPAは15秒ごとに**Metrics Server**（またはカスタムメトリクスAPI）をクエリします。
2. 計算：`desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`。
3. 希望するレプリカが現在と異なる場合、Deploymentのレプリカ数を更新します。
4. クールダウン期間が振動を防止：スケールアップ安定化（デフォルト0秒）、スケールダウン安定化（デフォルト300秒）。

要件：Metrics Serverがインストール済み、コンテナにリソースリクエストが定義済み（CPU/メモリメトリクス用）、最小/最大レプリカ境界が設定済み。
</details>

<details>
<summary><strong>20. livenessプローブとreadinessプローブの違いは何ですか？</strong></summary>
<br>

- **Livenessプローブ**：「コンテナは生きていますか？」失敗するとkubeletはコンテナを**キルして再起動**します。デッドロックやフリーズしたプロセスの検出に使用。
- **Readinessプローブ**：「コンテナはトラフィックを処理する準備ができていますか？」失敗するとPodは**Serviceエンドポイントから削除**され（トラフィックはルーティングされない）、コンテナは再起動されません。ウォームアップ期間、依存関係チェック、一時的な過負荷に使用。

また**Startupプローブ**があります：アプリが起動するまでliveness/readinessプローブを無効にします。早期キルを防ぐため、起動の遅いアプリケーションに有用です。

よくあるミス：下流の依存関係（データベース）をチェックするlivenessプローブの使用。データベースがダウンすると、すべてのPodが再起動し、障害を悪化させます。Livenessはアプリケーション自体のみをチェックすべきです。
</details>
