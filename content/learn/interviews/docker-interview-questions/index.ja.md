---
title: "Docker面接質問トップ20と回答（2026年版）"
description: "コンテナ、イメージ、ネットワーキング、ボリューム、Docker Compose、本番環境のベストプラクティスを網羅した20の高度なDocker質問で、シニアDevOps面接を突破しましょう。"
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["docker面接質問", "シニアdevops面接", "コンテナ化質問", "docker面接回答", "docker compose面接", "dockerfileベストプラクティス", "コンテナオーケストレーション面接", "dockerネットワーク質問", "devopsエンジニア面接", "docker本番質問"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker面接質問トップ20と回答（2026年版）",
    "description": "コンテナ、イメージ、ネットワーキング、本番環境のベストプラクティスを網羅したシニアDevOps向け高度なDocker面接質問。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ja"
  }
---

## システム初期化

Dockerは、DevOps、SRE、バックエンドエンジニアリングのいずれの職種でも必須のスキルとなっています。シニアレベルの面接官は`docker run`を超えた知識を期待しています — イメージのレイヤリング、ネットワーキングの内部構造、セキュリティの強化、本番環境向けのオーケストレーションパターンを理解していることを見たいのです。このガイドには、シニアおよびリードレベルの面接で最も頻繁に聞かれる20の質問と、深い知識を示す詳細な回答が含まれています。

**面接前にコマンドを素早く復習したいですか？** [Docker Captain's Logチートシート](/cheatsheets/docker-container-commands/)をブックマークしてください。

---

## 基本概念

<details>
<summary><strong>1. コンテナと仮想マシンの違いは何ですか？</strong></summary>
<br>

**仮想マシン**は、ハイパーバイザー上で完全なゲストOSを実行し、独自のカーネル、ドライバー、システムライブラリを含みます。各VMは完全に分離されていますが、大量のリソースを消費します（数GBのRAM、起動に数分）。

**コンテナ**はホストOSのカーネルを共有し、Linuxの名前空間とcgroupsを使用してプロセスを分離します。アプリケーションとその依存関係のみをパッケージ化し、別のカーネルは不要です。これによりコンテナは軽量（MB単位）、高速起動（ミリ秒）、高い移植性を実現しています。

主な違い：VMは**ハードウェア**を仮想化し、コンテナは**オペレーティングシステム**を仮想化します。
</details>

<details>
<summary><strong>2. Dockerイメージレイヤーとは何で、どのように機能しますか？</strong></summary>
<br>

Dockerイメージは一連の**読み取り専用レイヤー**から構築されます。Dockerfileの各命令（`FROM`、`RUN`、`COPY`など）が新しいレイヤーを作成します。レイヤーはユニオンファイルシステム（OverlayFSなど）を使用して積み重ねられます。

コンテナが実行されると、Dockerは上部に薄い**書き込み可能レイヤー**（コンテナレイヤー）を追加します。実行時の変更はこの書き込み可能レイヤーにのみ影響し、基盤となるイメージレイヤーは変更されません。

このアーキテクチャにより以下が可能になります：
- **キャッシング**：レイヤーが変更されていなければ、ビルド時にDockerはキャッシュから再利用します。
- **共有**：同じイメージからの複数のコンテナが読み取り専用レイヤーを共有し、ディスクスペースを節約します。
- **効率性**：変更されたレイヤーのみをレジストリからプルまたはプッシュする必要があります。
</details>

<details>
<summary><strong>3. DockerfileにおけるCMDとENTRYPOINTの違いは何ですか？</strong></summary>
<br>

両方ともコンテナ起動時に何を実行するかを定義しますが、動作が異なります：

- **CMD**は実行時に完全に上書きできるデフォルト引数を提供します。`docker run myimage /bin/bash`を実行すると、CMDが置き換えられます。
- **ENTRYPOINT**は常に実行されるメイン実行ファイルを定義します。実行時の引数はそれに追加され、置き換えられません。

ベストプラクティス：メインプロセスには`ENTRYPOINT`を、デフォルト引数には`CMD`を使用します：

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

`docker run myimage --port 3000`を実行すると`python app.py --port 3000`が実行されます。
</details>

<details>
<summary><strong>4. マルチステージビルドとは何で、なぜ重要ですか？</strong></summary>
<br>

マルチステージビルドは単一のDockerfileで複数の`FROM`命令を使用します。各`FROM`は新しいビルドステージを開始し、あるステージから別のステージに成果物を選択的にコピーできます。

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Stage 2: Run (minimal image)
FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

これによりコンパイル済みバイナリのみを含む最終イメージが生成されます — ビルドツールも、ソースコードも、中間ファイルもありません。結果として劇的に小さなイメージ（多くの場合10〜100倍小さい）が得られ、攻撃面が縮小されます。
</details>

<details>
<summary><strong>5. DockerfileにおけるCOPYとADDの違いは何ですか？</strong></summary>
<br>

両方ともビルドコンテキストからイメージにファイルをコピーしますが、`ADD`には追加機能があります：
- `ADD`はローカルの`.tar`アーカイブを自動的に展開できます。
- `ADD`はURLからファイルをダウンロードできます。

ただし、Dockerのベストプラクティスでは、明示的で予測可能な`COPY`をほぼすべてのケースで使用することを推奨しています。`ADD`はtar展開が具体的に必要な場合にのみ使用してください。ファイルのダウンロードには`ADD`を使用せず、代わりに`RUN curl`または`RUN wget`を使用してください。これによりダウンロードレイヤーが適切にキャッシュされます。
</details>

## ネットワーキング

<details>
<summary><strong>6. Dockerのネットワークモード（bridge、host、none、overlay）を説明してください。</strong></summary>
<br>

- **Bridge**（デフォルト）：ホスト上にプライベート内部ネットワークを作成します。同じブリッジ上のコンテナはIPまたはコンテナ名で通信できます。外部へのトラフィックにはポートマッピング（`-p`）が必要です。
- **Host**：ネットワーク分離を除去します。コンテナはホストのネットワークスタックを直接共有します。ポートマッピングは不要ですが、分離もありません。パフォーマンスが重要なアプリケーションに有用です。
- **None**：ネットワークなし。コンテナにはループバックインターフェースのみがあります。バッチジョブやセキュリティに敏感なワークロードに使用されます。
- **Overlay**：複数のDockerホストにまたがります（Swarm/Kubernetesで使用）。異なるマシン上のコンテナがVXLANトンネリングを使用して同じネットワーク上にいるかのように通信できます。
</details>

<details>
<summary><strong>7. コンテナ間通信はどのように機能しますか？</strong></summary>
<br>

ユーザー定義のブリッジネットワークでは、Dockerの組み込みDNSリゾルバーを通じて、コンテナは**コンテナ名で**互いに到達できます。DNSサーバーは各コンテナ内の`127.0.0.11`で実行されています。

デフォルトのブリッジネットワークでは、DNS解決は**利用できません** — コンテナはIPアドレスでのみ通信でき、IPは動的に割り当てられるため信頼性がありません。

ベストプラクティス：常にカスタムブリッジネットワーク（`docker network create mynet`）を作成し、コンテナをそれに接続してください。コンテナ間通信にデフォルトのブリッジを使用しないでください。
</details>

<details>
<summary><strong>8. EXPOSEとポートの公開の違いは何ですか？</strong></summary>
<br>

Dockerfileの`EXPOSE`は純粋に**ドキュメンテーション**です — Dockerfileを読む人にアプリケーションが特定のポートでリッスンしていることを伝えます。実際にはポートを開いたりマッピングしたりしません。

ポートの公開（`-p 8080:80`）は実際にホストポートをコンテナポートにマッピングするネットワークルールを作成し、コンテナの外部からサービスにアクセス可能にします。

`EXPOSE`ディレクティブにないポートも公開でき、`EXPOSE`だけでは`-p`なしでは何も行いません。
</details>

## ボリュームとストレージ

<details>
<summary><strong>9. Dockerの3種類のマウントは何ですか？</strong></summary>
<br>

1. **ボリューム**（`docker volume create`）：Dockerが管理し、`/var/lib/docker/volumes/`に保存されます。永続データ（データベース）に最適です。コンテナ削除後も存続します。ホスト間で移植可能です。
2. **バインドマウント**（`-v /host/path:/container/path`）：特定のホストディレクトリをコンテナにマッピングします。ホストパスが存在する必要があります。開発（ライブコードリロード）に最適です。移植性はありません。
3. **tmpfsマウント**（`--tmpfs /tmp`）：ホストのメモリにのみ保存されます。ディスクには書き込まれません。永続化すべきでない機密データ（シークレット、セッショントークン）に最適です。
</details>

<details>
<summary><strong>10. データベースコンテナのデータをどのように永続化しますか？</strong></summary>
<br>

データベースのデータディレクトリにマウントされた**名前付きボリューム**を使用します：

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

データはコンテナの再起動と削除後も存続します。データベースバージョンをアップグレードする際は、古いコンテナを停止し、同じボリュームで新しいコンテナを起動し、新しいバージョンにデータ移行を処理させます。

本番データベースにバインドマウントを使用しないでください — ボリュームはI/Oパフォーマンスが優れており、Dockerのストレージドライバーによって管理されます。
</details>

## セキュリティ

<details>
<summary><strong>11. 本番環境でDockerコンテナをどのように保護しますか？</strong></summary>
<br>

主なハードニングプラクティス：
- **非rootで実行**：Dockerfileで`USER`ディレクティブを使用します。アプリケーションプロセスをrootで実行しないでください。
- **最小限のベースイメージを使用**：`ubuntu`の代わりに`alpine`、`distroless`、または`scratch`を使用します。
- **ケイパビリティを削除**：`--cap-drop ALL --cap-add <必要なもののみ>`を使用します。
- **読み取り専用ファイルシステム**：`--read-only`を使用し、特定の書き込み可能パスのみをマウントします。
- **新しい特権なし**：`--security-opt=no-new-privileges`を使用します。
- **イメージをスキャン**：`docker scout`、Trivy、またはSnykを使用してベースイメージと依存関係の脆弱性を検出します。
- **イメージに署名**：Docker Content Trust（`DOCKER_CONTENT_TRUST=1`）を使用してイメージの真正性を検証します。
- **リソースを制限**：`--memory`、`--cpus`を使用してリソース枯渇を防止します。
</details>

<details>
<summary><strong>12. Dockerのrootlessモードとは何ですか？</strong></summary>
<br>

Dockerのrootlessモードは、ホスト上のroot権限を必要とせず、ユーザー名前空間内でDockerデーモンとコンテナを完全に実行します。これにより、Dockerの主要なセキュリティ上の懸念が排除されます：デーモンがrootとして実行され、コンテナエスケープがホストへのrootアクセスを意味するという問題です。

rootlessモードでは、攻撃者がコンテナから脱出しても、Dockerを実行している非特権ユーザーの権限しか得られません。トレードオフとして、一部の機能（1024未満のポートへのバインドなど）には追加の設定が必要です。
</details>

## Docker Composeとオーケストレーション

<details>
<summary><strong>13. docker-compose upとdocker-compose runの違いは何ですか？</strong></summary>
<br>

- `docker compose up`：`docker-compose.yml`で定義された**すべての**サービスを起動し、ネットワーク/ボリュームを作成し、`depends_on`の順序を尊重します。通常、スタック全体を立ち上げるために使用されます。
- `docker compose run <サービス> <コマンド>`：ワンオフコマンドで**単一の**サービスを起動します。デフォルトでは依存サービスを起動しません（ポートをマッピングするには`--service-ports`、クリーンアップには`--rm`を使用）。マイグレーション、テスト、または管理タスクの実行に使用されます。
</details>

<details>
<summary><strong>14. depends_onはどのように機能し、その制限は何ですか？</strong></summary>
<br>

`depends_on`は**起動順序**を制御します — サービスAがサービスBの前に起動することを保証します。ただし、コンテナが**起動**するのを待つだけで、内部のアプリケーションが**準備完了**になるのを待ちません。

例えば、データベースコンテナは数秒で起動するかもしれませんが、PostgreSQLは初期化に追加の時間が必要です。アプリコンテナは起動しますが、すぐに接続に失敗します。

解決策：`depends_on`を`condition`とヘルスチェックとともに使用します：

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5
  app:
    depends_on:
      db:
        condition: service_healthy
```
</details>

<details>
<summary><strong>15. Docker SwarmとKubernetesのどちらを選びますか？</strong></summary>
<br>

**Docker Swarm**：Dockerに組み込まれており、追加のセットアップは不要。シンプルさが重要な小中規模のデプロイメントに最適。同じDocker Composeファイルを使用。Kubernetesと比較してエコシステムとコミュニティが限られています。専任のプラットフォームエンジニアがいないチームに適しています。

**Kubernetes**：大規模なコンテナオーケストレーションの業界標準。オートスケーリング、ローリングアップデート、サービスメッシュ、カスタムリソース定義、巨大なエコシステム（Helm、Istio、ArgoCD）をサポート。複雑性と学習曲線が高い。大規模、マルチチーム、マルチクラウドのデプロイメントに必要。

経験則：20未満のサービスと小さなチームであれば、Swarmで十分です。それ以上であれば、Kubernetesへの投資は価値があります。
</details>

## 本番環境とトラブルシューティング

<details>
<summary><strong>16. Dockerイメージのサイズをどのように削減しますか？</strong></summary>
<br>

1. **マルチステージビルドを使用** — ビルドツールを最終イメージから除外します。
2. **最小限のベースイメージを使用** — `ubuntu`（〜75MB）の代わりに`alpine`（〜5MB）を使用します。
3. **RUNコマンドを統合** — 各`RUN`はレイヤーを作成します。`&&`でコマンドをチェーンし、同じレイヤーでクリーンアップします。
4. **.dockerignoreを使用** — `node_modules`、`.git`、テストファイル、ドキュメントをビルドコンテキストから除外します。
5. **変更頻度でレイヤーを順序付け** — キャッシュヒットを最大化するために、変更頻度の低いレイヤー（依存関係）を変更頻度の高いレイヤー（ソースコード）の前に配置します。
</details>

<details>
<summary><strong>17. コンテナが再起動を繰り返しています。どのようにデバッグしますか？</strong></summary>
<br>

ステップバイステップのアプローチ：
1. `docker ps -a` — 終了コードを確認します。終了コード137 = OOMキル。終了コード1 = アプリケーションエラー。
2. `docker logs <container>` — スタックトレースやエラーメッセージのためにアプリケーションログを読みます。
3. `docker inspect <container>` — `State.OOMKilled`、リソース制限、環境変数を確認します。
4. `docker run -it --entrypoint /bin/sh <image>` — 環境を手動でデバッグするためにインタラクティブシェルを起動します。
5. `docker stats` — コンテナがメモリまたはCPUの制限に達しているか確認します。
6. `docker events`を確認 — デーモンからのkillシグナルやOOMイベントを探します。
</details>

<details>
<summary><strong>18. docker stopとdocker killの違いは何ですか？</strong></summary>
<br>

- `docker stop`はメインプロセス（PID 1）に**SIGTERM**を送信し、猶予期間（デフォルト10秒）を待ちます。プロセスが終了しない場合、DockerはSIGKILLを送信します。これによりアプリケーションはグレースフルシャットダウン（接続のクローズ、バッファのフラッシュ、状態の保存）を実行できます。
- `docker kill`は即座に**SIGKILL**を送信します。プロセスはクリーンアップの機会なしに終了されます。コンテナが応答しない場合にのみ使用してください。

ベストプラクティス：本番環境では常に`docker stop`を使用してください。アプリケーションがSIGTERMを適切に処理することを確認してください。
</details>

<details>
<summary><strong>19. Dockerでシークレットをどのように管理しますか？</strong></summary>
<br>

シークレットをイメージに埋め込むことは**絶対に**しないでください（DockerfileのENV、.envファイルのCOPY）。イメージレイヤーに残り、`docker history`で確認できます。

成熟度レベル別のアプローチ：
- **基本**：実行時に`--env-file`でシークレットを渡します（ファイルはイメージに含まれません）。
- **より良い**：Docker SwarmシークレットまたはKubernetesシークレットを使用します（環境変数ではなく、ファイルとしてマウント）。
- **最良**：外部シークレットマネージャー（HashiCorp Vault、AWS Secrets Manager、Azure Key Vault）を使用し、サイドカーまたはinitコンテナを介して実行時にシークレットを注入します。
</details>

<details>
<summary><strong>20. Dockerヘルスチェックとは何で、なぜ重要ですか？</strong></summary>
<br>

ヘルスチェックは、Dockerがコンテナ内で定期的に実行するコマンドで、アプリケーションが実際に動作しているかを確認します — プロセスが実行中であるだけでなく。

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

ヘルスチェックなしでは、Dockerはプロセスが生きているか（PIDが存在するか）しか知りません。ヘルスチェックがあれば、Dockerはアプリケーションが**健全**か（リクエストに応答しているか）を知ります。これは以下にとって重要です：
- **ロードバランサー**：健全なコンテナにのみトラフィックをルーティングします。
- **オーケストレーター**：不健全なコンテナを自動的に再起動します。
- **depends_on**：プロセスの起動だけでなく、実際の準備完了を待ちます。
</details>
