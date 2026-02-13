---
title: "互联网地图：网络端口、协议与状态码"
description: "TCP/IP、OSI模型、常用端口（SSH、HTTP、DNS）和HTTP状态码的可视化指南，面向DevOps和安全人员。"
date: 2026-02-13
tags: ["networking", "cheatsheet", "devops", "security", "sysadmin"]
keywords: ["common ports cheat sheet", "http status codes", "tcp vs udp", "osi model explained", "dns records types", "ssh port forwarding"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "互联网地图：网络端口、协议与状态码",
    "description": "TCP/IP、OSI模型、常用端口（SSH、HTTP、DNS）和HTTP状态码的可视化指南，面向DevOps和安全人员。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## 常用端口

网络上的每个服务都在一个端口上监听。以下是你必须熟记的端口。

### 知名端口（0–1023）

| 端口 | 协议 | 服务 | 备注 |
|------|------|------|------|
| 20 | TCP | FTP 数据 | 主动模式数据传输 |
| 21 | TCP | FTP 控制 | 命令和身份验证 |
| 22 | TCP | SSH / SFTP | 安全 Shell 和文件传输 |
| 23 | TCP | Telnet | 未加密的远程访问（应避免使用） |
| 25 | TCP | SMTP | 邮件发送 |
| 53 | TCP/UDP | DNS | 域名解析 |
| 67/68 | UDP | DHCP | 动态 IP 分配 |
| 80 | TCP | HTTP | 未加密的网页流量 |
| 110 | TCP | POP3 | 邮件接收 |
| 143 | TCP | IMAP | 邮件接收（服务器端） |
| 443 | TCP | HTTPS | 加密的网页流量（TLS） |
| 445 | TCP | SMB | Windows 文件共享 |
| 587 | TCP | SMTP (TLS) | 安全邮件提交 |

### 注册端口（1024–49151）

| 端口 | 协议 | 服务 | 备注 |
|------|------|------|------|
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle 数据库监听器 |
| 3306 | TCP | MySQL | MySQL / MariaDB |
| 3389 | TCP | RDP | 远程桌面协议 |
| 5432 | TCP | PostgreSQL | PostgreSQL 数据库 |
| 5900 | TCP | VNC | 虚拟网络计算 |
| 6379 | TCP | Redis | 内存数据存储 |
| 8080 | TCP | HTTP Alt | 常用开发/代理端口 |
| 8443 | TCP | HTTPS Alt | 备用 HTTPS 端口 |
| 27017 | TCP | MongoDB | MongoDB 数据库 |

---

## HTTP 状态码

服务器告诉你发生了什么的方式。按类别分组。

### 1xx — 信息性

| 状态码 | 名称 | 含义 |
|--------|------|------|
| 100 | Continue | 继续发送请求体 |
| 101 | Switching Protocols | 升级到 WebSocket |

### 2xx — 成功

| 状态码 | 名称 | 含义 |
|--------|------|------|
| 200 | OK | 请求成功 |
| 201 | Created | 资源已创建（POST 成功） |
| 204 | No Content | 成功，但无内容返回 |

### 3xx — 重定向

| 状态码 | 名称 | 含义 |
|--------|------|------|
| 301 | Moved Permanently | URL 永久变更（更新书签） |
| 302 | Found | 临时重定向 |
| 304 | Not Modified | 使用缓存版本 |
| 307 | Temporary Redirect | 类似 302，但保持 HTTP 方法 |
| 308 | Permanent Redirect | 类似 301，但保持 HTTP 方法 |

### 4xx — 客户端错误

| 状态码 | 名称 | 含义 |
|--------|------|------|
| 400 | Bad Request | 语法错误或无效数据 |
| 401 | Unauthorized | 需要身份验证 |
| 403 | Forbidden | 已验证身份但无权限 |
| 404 | Not Found | 资源不存在 |
| 405 | Method Not Allowed | HTTP 方法错误（GET vs POST） |
| 408 | Request Timeout | 服务器等待超时 |
| 409 | Conflict | 状态冲突（例如重复） |
| 413 | Payload Too Large | 请求体超出限制 |
| 418 | I'm a Teapot | RFC 2324。没错，这是真的。 |
| 429 | Too Many Requests | 请求频率限制 |

### 5xx — 服务器错误

| 状态码 | 名称 | 含义 |
|--------|------|------|
| 500 | Internal Server Error | 通用服务器故障 |
| 502 | Bad Gateway | 上游服务器返回无效响应 |
| 503 | Service Unavailable | 服务器过载或正在维护 |
| 504 | Gateway Timeout | 上游服务器未及时响应 |

---

## TCP 与 UDP

两种传输层协议。不同的工具适用于不同的场景。

| 特性 | TCP | UDP |
|------|-----|-----|
| 连接方式 | 面向连接（握手） | 无连接（发送即忘） |
| 可靠性 | 保证交付，有序 | 不保证，无排序 |
| 速度 | 较慢（额外开销） | 较快（最小开销） |
| 头部大小 | 20–60 字节 | 8 字节 |
| 流量控制 | 有（窗口机制） | 无 |
| 使用场景 | Web、邮件、文件传输、SSH | DNS、流媒体、游戏、VoIP |

### TCP 三次握手

```
Client              Server
  |--- SYN ----------->|   1. Client sends SYN (seq=x)
  |<-- SYN-ACK --------|   2. Server replies SYN-ACK (seq=y, ack=x+1)
  |--- ACK ----------->|   3. Client sends ACK (ack=y+1)
  |                     |   Connection established
```

### TCP 连接断开

```
Client              Server
  |--- FIN ----------->|   1. Client initiates close
  |<-- ACK ------------|   2. Server acknowledges
  |<-- FIN ------------|   3. Server ready to close
  |--- ACK ----------->|   4. Client confirms
  |                     |   Connection closed
```

---

## SSL/TLS 握手

HTTPS 如何建立加密连接。

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

关键概念：
- **非对称加密**（RSA/ECDSA）仅用于握手阶段
- **对称加密**（AES）用于实际数据传输（更快）
- **TLS 1.3** 将握手减少到 1 次往返（TLS 1.2 需要 2 次）

---

## OSI 模型

七层结构，从物理电缆到你的浏览器。每一层与对端的对等层通信。

| 层 | 名称 | 协议示例 | 数据单元 | 设备 |
|----|------|----------|----------|------|
| 7 | 应用层 | HTTP, FTP, DNS, SMTP | 数据 | — |
| 6 | 表示层 | SSL/TLS, JPEG, ASCII | 数据 | — |
| 5 | 会话层 | NetBIOS, RPC | 数据 | — |
| 4 | 传输层 | TCP, UDP | 段/数据报 | — |
| 3 | 网络层 | IP, ICMP, ARP | 数据包 | 路由器 |
| 2 | 数据链路层 | Ethernet, Wi-Fi, PPP | 帧 | 交换机 |
| 1 | 物理层 | 电缆、无线电、光纤 | 比特 | 集线器 |

> **助记口诀（从上到下）：** **应**用 **表**示 **会**话 **传**输 **网**络 **数**据 **物**理

### TCP/IP 模型（简化版）

| TCP/IP 层 | 对应 OSI 层 | 示例 |
|-----------|-------------|------|
| 应用层 | 7, 6, 5 | HTTP, DNS, SSH |
| 传输层 | 4 | TCP, UDP |
| 网际层 | 3 | IP, ICMP |
| 网络接入层 | 2, 1 | Ethernet, Wi-Fi |

---

## DNS 记录类型

域名如何映射到服务。

| 类型 | 用途 | 示例 |
|------|------|------|
| A | 域名 → IPv4 | `example.com → 93.184.216.34` |
| AAAA | 域名 → IPv6 | `example.com → 2606:2800:...` |
| CNAME | 别名到另一个域名 | `www.example.com → example.com` |
| MX | 邮件服务器 | `example.com → mail.example.com` |
| TXT | 验证、SPF、DKIM | `v=spf1 include:_spf.google.com` |
| NS | 域名服务器委派 | `example.com → ns1.provider.com` |
| SOA | 区域权威信息 | Serial, refresh, retry, expire |
| SRV | 服务位置 | `_sip._tcp.example.com` |
| PTR | 反向查找（IP → 域名） | `34.216.184.93 → example.com` |

---

## SSH 端口转发

通过 SSH 隧道传输流量。访问防火墙后面的服务时必不可少。

```bash
# Local forwarding: access remote_host:3306 via localhost:9906
ssh -L 9906:localhost:3306 user@remote_host

# Remote forwarding: expose your localhost:3000 on remote:8080
ssh -R 8080:localhost:3000 user@remote_host

# Dynamic forwarding (SOCKS proxy on localhost:1080)
ssh -D 1080 user@remote_host

# Tunnel through a jump host
ssh -J jump_host user@final_host
```

---

## 快速参考表

| 用途 | 命令 / 值 |
|------|-----------|
| 检查开放端口 | `ss -tlnp` 或 `netstat -tlnp` |
| 扫描端口 | `nmap -sV target` |
| DNS 查询 | `dig example.com A` 或 `nslookup example.com` |
| 路由追踪 | `traceroute example.com` |
| 测试连通性 | `ping -c 4 example.com` |
| HTTP 请求 | `curl -I https://example.com` |
| 检查 TLS 证书 | `openssl s_client -connect example.com:443` |
| 抓包 | `tcpdump -i eth0 port 80` |
