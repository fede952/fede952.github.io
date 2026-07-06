---
title: "SafeEnv：.env 文件密钥与 API Key 扫描器"
description: "在提交代码前扫描你的 .env 文件和配置片段，找出暴露的密钥 —— AWS 密钥、GitHub 和 Stripe 令牌、私钥、URL 中的密码以及高熵值。100% 在浏览器中运行，绝不上传任何内容。"
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["env 文件扫描", "密钥扫描器", "api key 检查", "检测泄露密钥", "扫描 env", "aws 密钥泄露", "git secrets", "客户端密钥扫描器", "dotenv 安全"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv —— 密钥与 API Key 扫描器", "description": "免费的客户端扫描器，在提交前找出 .env 文件和配置中暴露的 API 密钥、令牌、私钥和密码。", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## 为什么要在提交前扫描

只需一个被贴进公开仓库的 `.env` 就够了：机器人持续爬取 GitHub，**不到一分钟**就能找到新泄露的 AWS 密钥。SafeEnv 在提交前拦截泄露。粘贴任意配置 —— `.env`、`docker-compose.yml`、CI 配置、源码片段 —— 它会标出暴露的凭据，附带行号、掩码预览和具体的修复步骤。

扫描完全在本页面的内存中进行。没有上传、没有日志、没有网络请求 —— 对于一个要粘贴真实密钥的工具来说，这是唯一可接受的设计。刷新页面，一切即被清除。

## 检测内容

- **云与 API 令牌** —— AWS 密钥、GitHub、GitLab、Stripe、Google、OpenAI、Anthropic、Slack、SendGrid、npm、PyPI、Telegram、Twilio
- **私钥** —— RSA/EC/OpenSSH/PGP PEM 块
- **URL 中的凭据** —— 内嵌密码的数据库连接串和 basic-auth URL
- **通用泄露** —— 硬编码密码和高熵值，并通过占位符识别降低误报

粘贴配置开始扫描，或加载示例查看所有检测器对伪造密钥的响应。
