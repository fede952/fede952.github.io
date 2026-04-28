---
title: "インターネットの地図：ネットワークポート、プロトコル、ステータスコード"
description: "TCP/IP、OSIモデル、主要ポート（SSH、HTTP、DNS）、HTTPステータスコードのビジュアルガイド。DevOpsとハッカー向け。"
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "インターネットの地図：ネットワークポート、プロトコル、ステータスコード",
    "description": "TCP/IP、OSIモデル、主要ポート（SSH、HTTP、DNS）、HTTPステータスコードのビジュアルガイド。DevOpsとハッカー向け。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## 主要ポート

ネットワーク上のすべてのサービスはポートでリッスンしている。これらは必ず覚えておくべきものだ。

### ウェルノウンポート（0〜1023）

| ポート | プロトコル | サービス | 備考 |
|--------|-----------|---------|------|
| 20 | TCP | FTP データ | アクティブモードのデータ転送 |
| 21 | TCP | FTP 制御 | コマンドと認証 |
| 22 | TCP | SSH / SFTP | セキュアシェルとファイル転送 |
| 23 | TCP | Telnet | 暗号化されないリモートアクセス（非推奨） |
| 25 | TCP | SMTP | メール送信 |
| 53 | TCP/UDP | DNS | ドメイン名前解決 |
| 67/68 | UDP | DHCP | 動的IPアドレスの割り当て |
| 80 | TCP | HTTP | 暗号化されないWebトラフィック |
| 110 | TCP | POP3 | メール受信 |
| 143 | TCP | IMAP | メール受信（サーバー側管理） |
| 443 | TCP | HTTPS | 暗号化されたWebトラフィック（TLS） |
| 445 | TCP | SMB | Windowsファイル共有 |
| 587 | TCP | SMTP (TLS) | セキュアなメール送信 |

### 登録済みポート（1024〜49151）

| ポート | プロトコル | サービス | 備考 |
|--------|-----------|---------|------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracleデータベースリスナー |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | リモートデスクトッププロトコル |
| 5432 | TCP | PostgreSQL | PostgreSQLデータベース |
| 5900 | TCP | VNC | 仮想ネットワークコンピューティング |
| 6379 | TCP | Redis | インメモリデータストア |
| 8080 | TCP | HTTP Alt | 開発/プロキシでよく使われるポート |
| 8443 | TCP | HTTPS Alt | 代替HTTPSポート |
| 27017 | TCP | MongoDB | MongoDBデータベース |

---

## HTTPステータスコード

サーバーが何が起きたかを伝える方法。カテゴリ別にまとめた。

### 1xx — 情報

| コード | 名前 | 意味 |
|--------|------|------|
| 100 | Continue | リクエストボディの送信を続けてよい |
| 101 | Switching Protocols | WebSocketへのアップグレード |

### 2xx — 成功

| コード | 名前 | 意味 |
|--------|------|------|
| 200 | OK | リクエスト成功 |
| 201 | Created | リソースが作成された（POSTの成功） |
| 204 | No Content | 成功したが返すものがない |

### 3xx — リダイレクト

| コード | 名前 | 意味 |
|--------|------|------|
| 301 | Moved Permanently | URLが恒久的に変更された（ブックマークを更新せよ） |
| 302 | Found | 一時的なリダイレクト |
| 304 | Not Modified | キャッシュ版を使用せよ |
| 307 | Temporary Redirect | 302と同様だがHTTPメソッドを維持 |
| 308 | Permanent Redirect | 301と同様だがHTTPメソッドを維持 |

### 4xx — クライアントエラー

| コード | 名前 | 意味 |
|--------|------|------|
| 400 | Bad Request | 不正な構文または無効なデータ |
| 401 | Unauthorized | 認証が必要 |
| 403 | Forbidden | 認証済みだが権限がない |
| 404 | Not Found | リソースが存在しない |
| 405 | Method Not Allowed | HTTPメソッドが間違っている（GET vs POST） |
| 408 | Request Timeout | サーバーが待ちきれなくなった |
| 409 | Conflict | 状態の競合（例：重複） |
| 413 | Payload Too Large | リクエストボディが制限を超えている |
| 418 | I'm a Teapot | RFC 2324。はい、本物です。 |
| 429 | Too Many Requests | レート制限に達した |

### 5xx — サーバーエラー

| コード | 名前 | 意味 |
|--------|------|------|
| 500 | Internal Server Error | 一般的なサーバー障害 |
| 502 | Bad Gateway | 上流サーバーが不正なレスポンスを送信した |
| 503 | Service Unavailable | サーバーが過負荷またはメンテナンス中 |
| 504 | Gateway Timeout | 上流サーバーが時間内に応答しなかった |

---

## TCP vs UDP

2つのトランスポート層プロトコル。用途に応じた異なるツール。

| 特徴 | TCP | UDP |
|------|-----|-----|
| 接続 | コネクション型（ハンドシェイク） | コネクションレス型（撃ちっぱなし） |
| 信頼性 | 配信保証あり、順序保証あり | 保証なし、順序保証なし |
| 速度 | 低速（オーバーヘッドあり） | 高速（オーバーヘッド最小） |
| ヘッダーサイズ | 20〜60バイト | 8バイト |
| フロー制御 | あり（ウィンドウ制御） | なし |
| 用途 | Web、メール、ファイル転送、SSH | DNS、ストリーミング、ゲーム、VoIP |

### TCP スリーウェイハンドシェイク

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### TCP コネクション切断

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## SSL/TLSハンドシェイク

HTTPSが暗号化接続を確立する仕組み。

```
Client                          Server
  |--- ClientHello ------------->|   Supported ciphers, TLS version, random
  |<-- ServerHello --------------|   Chosen cipher, certificate, random
  |    (verify certificate)      |
  |--- Key Exchange ------------>|   Pre-master secret (encrypted with server's public key)
  |    (both derive session key) |
  |--- Finished (encrypted) --->|   First encrypted message
  |<-- Finished (encrypted) ----|   Server confirms
  |                              |   Encrypted communication begins
```

重要な概念：
- **非対称暗号化**（RSA/ECDSA）はハンドシェイクにのみ使用される
- **対称暗号化**（AES）は実際のデータ転送に使用される（より高速）
- **TLS 1.3** はハンドシェイクを1ラウンドトリップに短縮した（TLS 1.2では2ラウンドトリップ）

---

## OSIモデル

物理ケーブルからブラウザまでの7つの層。各層は反対側の対応する層と通信する。

| 層 | 名前 | プロトコル例 | データ単位 | デバイス |
|----|------|-------------|-----------|---------|
| 7 | アプリケーション層 | HTTP, FTP, DNS, SMTP | データ | — |
| 6 | プレゼンテーション層 | SSL/TLS, JPEG, ASCII | データ | — |
| 5 | セッション層 | NetBIOS, RPC | データ | — |
| 4 | トランスポート層 | TCP, UDP | セグメント/データグラム | — |
| 3 | ネットワーク層 | IP, ICMP, ARP | パケット | ルーター |
| 2 | データリンク層 | Ethernet, Wi-Fi, PPP | フレーム | スイッチ |
| 1 | 物理層 | ケーブル, 無線, 光ファイバー | ビット | ハブ |

> **覚え方（上から下へ）：** **ア**プリケーション・**プ**レゼンテーション・**セ**ッション・**ト**ランスポート・**ネ**ットワーク・**デ**ータリンク・**ブ**ツリ → 「アプセトネデブ」

### TCP/IPモデル（簡略版）

| TCP/IP層 | OSI対応層 | 例 |
|----------|----------|-----|
| アプリケーション層 | 7, 6, 5 | HTTP, DNS, SSH |
| トランスポート層 | 4 | TCP, UDP |
| インターネット層 | 3 | IP, ICMP |
| ネットワークアクセス層 | 2, 1 | Ethernet, Wi-Fi |

---

## DNSレコードタイプ

ドメイン名がサービスにマッピングされる仕組み。

| タイプ | 用途 | 例 |
|--------|------|-----|
| A | ドメイン → IPv4 | `example.com → 93.184.216.34` |
| AAAA | ドメイン → IPv6 | `example.com → 2606:2800:...` |
| CNAME | 別のドメインへのエイリアス | `www.example.com → example.com` |
| MX | メールサーバー | `example.com → mail.example.com` |
| TXT | 検証、SPF、DKIM | `v=spf1 include:_spf.google.com` |
| NS | ネームサーバー委任 | `example.com → ns1.provider.com` |
| SOA | ゾーン権威情報 | シリアル、リフレッシュ、リトライ、有効期限 |
| SRV | サービスロケーション | `_sip._tcp.example.com` |
| PTR | 逆引き（IP → ドメイン） | `34.216.184.93 → example.com` |

---

## SSHポートフォワーディング

SSHを通じてトラフィックをトンネルする。ファイアウォールの背後にあるサービスへのアクセスに不可欠。

```bash
# ローカルフォワーディング：localhost:9906経由でremote_host:3306にアクセス
ssh -L 9906:localhost:3306 user@remote_host

# リモートフォワーディング：localhost:3000をリモートの8080で公開
ssh -R 8080:localhost:3000 user@remote_host

# ダイナミックフォワーディング（localhost:1080にSOCKSプロキシ）
ssh -D 1080 user@remote_host

# ジャンプホストを経由してトンネル
ssh -J jump_host user@final_host
```

---

## クイックリファレンス表

| 目的 | コマンド / 値 |
|------|--------------|
| 開いているポートを確認する | `ss -tlnp` or `netstat -tlnp` |
| ポートをスキャンする | `nmap -sV target` |
| DNS検索 | `dig example.com A` or `nslookup example.com` |
| 経路を追跡する | `traceroute example.com` |
| 接続性をテストする | `ping -c 4 example.com` |
| HTTPリクエスト | `curl -I https://example.com` |
| TLS証明書を確認する | `openssl s_client -connect example.com:443` |
| パケットをキャプチャする | `tcpdump -i eth0 port 80` |
