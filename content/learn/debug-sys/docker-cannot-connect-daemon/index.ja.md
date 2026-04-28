---
title: "修正: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "'Cannot connect to the Docker daemon' エラーを数秒で解決。サービスの問題か権限の問題かを判断し、恒久的に修正する方法を学びます。"
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "修正: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "LinuxでのDockerデーモン接続エラーのステップバイステップ修正ガイド。",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ja"
  }
---

## エラー内容

Dockerコマンドを実行すると、次のエラーが表示されます：

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

または、このバリエーション：

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

これはLinuxで最も一般的なDockerエラーの一つです。シェルがDockerエンジンと通信できないことを意味します。原因は常に次の2つのいずれかです：Dockerサービスが実行されていないか、ユーザーにDockerソケットへのアクセス権限がないかです。

---

## クイックフィックス

### 1. Dockerサービスを起動する

デーモンが単に実行されていない可能性があります。起動しましょう：

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

`status` が `active (running)` と表示されれば、サービスは稼働しています。Dockerコマンドを再度試してください。

### 2. ユーザー権限を修正する

サービスが実行中なのに "permission denied" が表示される場合、ユーザーが `docker` グループに所属していません：

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

この操作の後、`sudo` なしで `docker ps` を実行できるようになります。

---

## 詳細説明

DockerはUnixソケット（`/var/run/docker.sock`）を使用して、CLIクライアントとDockerデーモン（バックグラウンドサービス）間の通信を行います。これが機能するには、2つの条件が満たされている必要があります：

**1. Dockerデーモンが実行されていること。** systemdサービス `docker.service` がデーモンを管理しています。マシンが起動したばかりでDockerがスタートアップ時に有効化されていない場合、またはサービスがクラッシュした場合、ソケットファイルが存在しないか接続を受け付けていません。

**2. ユーザーがソケットにアクセスできること。** デフォルトでは、Dockerソケットは `root:docker` が所有し、権限は `srw-rw----` です。これは、rootと `docker` グループのメンバーのみがソケットに読み書きできることを意味します。ユーザーが `docker` グループに所属していない場合、すべてのコマンドに `sudo` が必要です。

### どちらの問題か？

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

`systemctl is-active` が `inactive` を返す場合 → **サービスの問題**です（修正 #1）。
サービスが `active` なのに permission denied が表示される場合 → **権限の問題**です（修正 #2）。

---

## よくある落とし穴

- **SnapでインストールしたDocker**：公式リポジトリの代わりにSnapでDockerをインストールした場合、ソケットパスとサービス名が異なる場合があります。Snap版をアンインストールし、公式のDocker CEパッケージを使用してください。
- **Windows上のWSL2**：DockerデーモンはWSL2でネイティブに動作しません。Docker Desktop for Windowsが実行されている必要があるか、WSL2ディストリビューション内でデーモンを手動でインストールして起動する必要があります。
- **Mac/Linux上のDocker Desktop**：Docker Desktopを使用している場合、デーモンはsystemdではなくDesktopアプリによって管理されています。Docker Desktopが開いて実行されていることを確認してください。

---

## 関連リソース

このエラーの再発を防ぎましょう。当サイトの完全な [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) をブックマークしてください — ユーザー権限、サービス管理、本番環境で必要なすべての `docker` コマンドを網羅しています。

Linuxのサービスとユーザーを管理する必要がありますか？ [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/) をご覧ください。
