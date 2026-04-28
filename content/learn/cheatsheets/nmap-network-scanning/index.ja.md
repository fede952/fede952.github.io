---
title: "Nmapフィールドマニュアル：ネットワーク偵察コマンド"
description: "ネットワークスキャン、ホスト検出、ポート列挙、サービス検出、脆弱性評価のための必須Nmapコマンド。ペネトレーションテスター向けの戦術的クイックリファレンス。"
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "nmapコマンド", "ネットワークスキャンガイド", "nmapポートスキャン", "nmapサービス検出", "nmapスクリプトNSE", "nmap脆弱性スキャン", "ペネトレーションテストコマンド"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Nmapフィールドマニュアル：ネットワーク偵察コマンド",
    "description": "ネットワークスキャン、ホスト検出、ポート列挙、脆弱性評価のための必須Nmapコマンド。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## $ System_Init

Nmapは、あらゆる偵察活動で最初にロードされるツールです。攻撃面をマッピングし、稼働中のホストを識別し、開いているポートを列挙し、サービスをフィンガープリントし、脆弱性を検出します — すべて単一のバイナリから。このフィールドマニュアルは、ネットワーク偵察の各段階における正確なコマンドを提供します。

すべてのコマンドは許可されたテストを前提としています。責任を持って展開してください。

---

## $ Host_Discovery

ポートスキャンの前にネットワーク上の稼働中のターゲットを識別する。

### Pingスイープ（ICMPエコー）

```bash
# ICMPピングを使用してサブネット上の稼働中のホストを検出
nmap -sn 192.168.1.0/24
```

### ARP検出（ローカルネットワークのみ）

```bash
# ローカルLAN上のホスト検出にARPリクエストを使用（最速の方法）
nmap -sn -PR 192.168.1.0/24
```

### 特定ポートでのTCP SYN検出

```bash
# 一般的なポートにSYNパケットを送信してホストを検出
nmap -sn -PS22,80,443 10.0.0.0/24
```

### DNS解決の無効化（スキャンを高速化）

```bash
# 逆引きDNSルックアップをスキップしてより速い結果を得る
nmap -sn -n 192.168.1.0/24
```

### リストスキャン（パケット送信なし）

```bash
# パケットを送信せずにスキャンされるターゲットをリスト化
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

開いているポートを列挙してターゲットの攻撃面をマッピングする。

### SYNスキャン（ステルススキャン — デフォルト）

```bash
# ハーフオープンスキャン：SYNを送信、SYN/ACKを受信、RSTを送信（ハンドシェイクを完了しない）
sudo nmap -sS 192.168.1.100
```

### TCP接続スキャン（root不要）

```bash
# 完全なTCPハンドシェイクスキャン（遅いが権限昇格なしで動作）
nmap -sT 192.168.1.100
```

### UDPスキャン

```bash
# 開いているUDPポートをスキャン（プロトコルの動作により遅い）
sudo nmap -sU 192.168.1.100
```

### 特定ポートのスキャン

```bash
# 特定のポートのみをスキャン
nmap -p 22,80,443,8080 192.168.1.100

# ポート範囲をスキャン
nmap -p 1-1024 192.168.1.100

# 全65535ポートをスキャン
nmap -p- 192.168.1.100
```

### トップポートスキャン

```bash
# 最も一般的に開いている100個のポートをスキャン
nmap --top-ports 100 192.168.1.100
```

### 高速スキャン（トップ100ポート）

```bash
# 迅速な評価のためにポート数を減らした高速スキャン
nmap -F 192.168.1.100
```

---

## $ Service_Detection

各開いているポートで実行されているソフトウェアを識別する。

### バージョン検出

```bash
# 開いているポートを調査してサービス名とバージョンを特定
nmap -sV 192.168.1.100
```

### 積極的バージョン検出

```bash
# 検出強度を上げる（1-9、デフォルト7）
nmap -sV --version-intensity 9 192.168.1.100
```

### OSフィンガープリンティング

```bash
# TCP/IPスタック分析を使用してターゲットのOSを検出
sudo nmap -O 192.168.1.100
```

### サービス + OS検出の組み合わせ

```bash
# OSフィンガープリンティング付きの完全なサービス列挙
sudo nmap -sV -O 192.168.1.100
```

### 積極的スキャン（OS + バージョン + スクリプト + traceroute）

```bash
# すべての検出機能を1つのフラグで有効化
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — 自動化された脆弱性検出と列挙。

### デフォルトスクリプトの実行

```bash
# 安全で情報提供的なデフォルトスクリプトセットを実行
nmap -sC 192.168.1.100
```

### 特定スクリプトの実行

```bash
# 名前で単一のNSEスクリプトを実行
nmap --script=http-title 192.168.1.100
```

### スクリプトカテゴリーの実行

```bash
# すべての脆弱性検出スクリプトを実行
nmap --script=vuln 192.168.1.100

# すべての検出スクリプトを実行
nmap --script=discovery 192.168.1.100

# 認証サービスに対するブルートフォーススクリプトを実行
nmap --script=brute 192.168.1.100
```

### HTTP列挙

```bash
# Webサーバーのディレクトリとファイルを列挙
nmap --script=http-enum 192.168.1.100

# Webアプリケーションファイアウォールを検出
nmap --script=http-waf-detect 192.168.1.100
```

### SMB列挙

```bash
# SMB共有とユーザーを列挙（Windowsネットワーク）
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### SSL/TLS分析

```bash
# SSL証明書の詳細と暗号スイートを確認
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

許可されたペネトレーションテスト中にファイアウォールとIDSをバイパスする。

### パケットの断片化

```bash
# 単純なパケットフィルタをバイパスするためにプローブパケットを小さな断片に分割
sudo nmap -f 192.168.1.100
```

### デコイスキャン

```bash
# 実際のスキャナーをマスクするために偽装された送信元IPを生成
sudo nmap -D RND:10 192.168.1.100
```

### 送信元ポートの偽装

```bash
# ポートベースのファイアウォールルールをバイパスするために信頼された送信元ポートを使用
sudo nmap --source-port 53 192.168.1.100
```

### タイミング制御

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### アイドルスキャン（ゾンビスキャン）

```bash
# IPを公開せずにスキャンするためにサードパーティの"ゾンビ"ホストを使用
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

ドキュメント化と後処理のためにスキャン結果を保存する。

### 通常出力

```bash
# 人間が読める形式で結果を保存
nmap -oN scan_results.txt 192.168.1.100
```

### XML出力（ツール用）

```bash
# XML形式で結果を保存（Metasploitなどで解析可能）
nmap -oX scan_results.xml 192.168.1.100
```

### Grep可能出力

```bash
# スクリプト用のgrep対応形式で結果を保存
nmap -oG scan_results.gnmap 192.168.1.100
```

### すべての形式を一度に

```bash
# 通常、XML、grep可能形式で同時に保存
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

一般的なエンゲージメントシナリオ用のコピー＆ペーストコマンドチェーン。

### クイック偵察

```bash
# ターゲットの迅速な初期評価
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### サービス検出付き完全ポートスキャン

```bash
# バージョン検出付きのすべてのポートの包括的スキャン
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### 脆弱性評価

```bash
# サービス検出と脆弱性スクリプト
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### ステルス偵察（最小限のフットプリント）

```bash
# アクティブな監視がある環境向けのローププロファイルスキャン
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
