---
title: "Nmap 实战手册：网络侦察命令"
description: "用于网络扫描、主机发现、端口枚举、服务检测和漏洞评估的基本 Nmap 命令。渗透测试人员的战术速查手册。"
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "nmap命令", "网络扫描指南", "nmap端口扫描", "nmap服务检测", "nmap脚本NSE", "nmap漏洞扫描", "渗透测试命令"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Nmap 实战手册：网络侦察命令",
    "description": "用于网络扫描、主机发现、端口枚举和漏洞评估的基本 Nmap 命令。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## $ System_Init

Nmap 是任何侦察活动中首先加载的工具。它绘制攻击面、识别活动主机、枚举开放端口、指纹识别服务并检测漏洞 — 全部来自单个二进制文件。本实战手册提供网络侦察每个阶段的精确命令。

所有命令均假设已获得授权测试。请负责任地部署。

---

## $ Host_Discovery

在端口扫描之前识别网络上的活动目标。

### Ping 扫描（ICMP 回显）

```bash
# 使用 ICMP ping 发现子网上的活动主机
nmap -sn 192.168.1.0/24
```

### ARP 发现（仅本地网络）

```bash
# 在本地局域网上使用 ARP 请求进行主机发现（最快方法）
nmap -sn -PR 192.168.1.0/24
```

### 特定端口上的 TCP SYN 发现

```bash
# 通过向常见端口发送 SYN 数据包来发现主机
nmap -sn -PS22,80,443 10.0.0.0/24
```

### 禁用 DNS 解析（加速扫描）

```bash
# 跳过反向 DNS 查找以获得更快的结果
nmap -sn -n 192.168.1.0/24
```

### 列表扫描（不发送数据包）

```bash
# 列出将被扫描的目标而不发送任何数据包
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

枚举开放端口以绘制目标的攻击面。

### SYN 扫描（隐秘扫描 — 默认）

```bash
# 半开放扫描：发送 SYN，接收 SYN/ACK，发送 RST（从不完成握手）
sudo nmap -sS 192.168.1.100
```

### TCP 连接扫描（不需要 root）

```bash
# 完整的 TCP 握手扫描（较慢但无需提升权限即可工作）
nmap -sT 192.168.1.100
```

### UDP 扫描

```bash
# 扫描开放的 UDP 端口（由于协议行为较慢）
sudo nmap -sU 192.168.1.100
```

### 扫描特定端口

```bash
# 仅扫描特定端口
nmap -p 22,80,443,8080 192.168.1.100

# 扫描端口范围
nmap -p 1-1024 192.168.1.100

# 扫描所有 65535 个端口
nmap -p- 192.168.1.100
```

### 热门端口扫描

```bash
# 扫描最常开放的 100 个端口
nmap --top-ports 100 192.168.1.100
```

### 快速扫描（前 100 个端口）

```bash
# 减少端口数量的快速扫描以进行快速评估
nmap -F 192.168.1.100
```

---

## $ Service_Detection

识别每个开放端口上运行的软件。

### 版本检测

```bash
# 探测开放端口以确定服务名称和版本
nmap -sV 192.168.1.100
```

### 激进版本检测

```bash
# 增加检测强度（1-9，默认 7）
nmap -sV --version-intensity 9 192.168.1.100
```

### 操作系统指纹识别

```bash
# 使用 TCP/IP 堆栈分析检测目标的操作系统
sudo nmap -O 192.168.1.100
```

### 服务 + 操作系统检测组合

```bash
# 带有操作系统指纹识别的完整服务枚举
sudo nmap -sV -O 192.168.1.100
```

### 激进扫描（操作系统 + 版本 + 脚本 + traceroute）

```bash
# 在一个标志中启用所有检测功能
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap 脚本引擎 — 自动化漏洞检测和枚举。

### 运行默认脚本

```bash
# 执行默认的安全信息脚本集
nmap -sC 192.168.1.100
```

### 运行特定脚本

```bash
# 按名称执行单个 NSE 脚本
nmap --script=http-title 192.168.1.100
```

### 运行脚本类别

```bash
# 运行所有漏洞检测脚本
nmap --script=vuln 192.168.1.100

# 运行所有发现脚本
nmap --script=discovery 192.168.1.100

# 对认证服务运行暴力破解脚本
nmap --script=brute 192.168.1.100
```

### HTTP 枚举

```bash
# 枚举 Web 服务器目录和文件
nmap --script=http-enum 192.168.1.100

# 检测 Web 应用防火墙
nmap --script=http-waf-detect 192.168.1.100
```

### SMB 枚举

```bash
# 枚举 SMB 共享和用户（Windows 网络）
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### SSL/TLS 分析

```bash
# 检查 SSL 证书详细信息和密码套件
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

在获得授权的渗透测试期间绕过防火墙和 IDS。

### 分段数据包

```bash
# 将探测数据包拆分为更小的片段以绕过简单的数据包过滤器
sudo nmap -f 192.168.1.100
```

### 诱饵扫描

```bash
# 生成伪造的源 IP 以掩盖真实的扫描器
sudo nmap -D RND:10 192.168.1.100
```

### 伪造源端口

```bash
# 使用受信任的源端口绕过基于端口的防火墙规则
sudo nmap --source-port 53 192.168.1.100
```

### 时序控制

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### 空闲扫描（僵尸扫描）

```bash
# 使用第三方"僵尸"主机扫描而不透露您的 IP
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

保存扫描结果用于文档记录和后处理。

### 正常输出

```bash
# 以人类可读格式保存结果
nmap -oN scan_results.txt 192.168.1.100
```

### XML 输出（用于工具）

```bash
# 以 XML 格式保存结果（可由 Metasploit 等解析）
nmap -oX scan_results.xml 192.168.1.100
```

### 可 Grep 输出

```bash
# 以 grep 友好格式保存结果用于脚本编写
nmap -oG scan_results.gnmap 192.168.1.100
```

### 同时所有格式

```bash
# 同时以正常、XML 和可 grep 格式保存
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

常见场景的复制粘贴命令链。

### 快速侦察

```bash
# 目标的快速初始评估
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### 带服务检测的全端口扫描

```bash
# 带版本检测的所有端口全面扫描
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### 漏洞评估

```bash
# 服务检测加漏洞脚本
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### 隐秘侦察（最小足迹）

```bash
# 适用于具有主动监控环境的低调扫描
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
