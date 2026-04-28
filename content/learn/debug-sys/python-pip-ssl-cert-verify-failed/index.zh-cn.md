---
title: "修复: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "修复由企业代理、缺失证书或过时的Python安装引起的pip SSL CERTIFICATE_VERIFY_FAILED错误。包含多种解决方案。"
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "修复: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "如何在Windows、Linux和macOS上修复pip的SSL CERTIFICATE_VERIFY_FAILED错误。",
    "proficiencyLevel": "Beginner",
    "inLanguage": "zh-CN"
  }
---

## 错误信息

运行 `pip install` 时出现以下错误之一：

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

或更简短的变体：

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

包下载失败，因为pip无法验证PyPI（Python包注册中心）的SSL证书。这几乎总是由拦截HTTPS流量的企业代理、缺失的系统证书或过时的Python/pip安装引起的。

---

## 快速修复

### 修复 1：绕过SSL验证（即时解决方法）

告诉pip在不验证证书的情况下信任PyPI主机：

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

要使其永久生效，请将其添加到pip配置中：

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### 修复 2：更新证书（正确修复）

真正的解决方案是确保系统拥有最新的CA证书：

```bash
# Update pip itself first
python -m pip install --upgrade pip

# Install/update the certifi package (Python's certificate bundle)
pip install --upgrade certifi

# On macOS: Run the certificate installer
# (Navigate to Applications/Python X.X/ and run "Install Certificates.command")
# Or from terminal:
/Applications/Python\ 3.x/Install\ Certificates.command
```

### 修复 3：企业代理证书

如果你在拦截HTTPS的企业代理（MITM）后面，需要将公司的CA证书添加到Python的信任存储中：

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

或设置环境变量指向自定义CA证书包：

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## 原因解析

当pip连接到 `https://pypi.org` 时，它会执行TLS握手并根据受信任的证书颁发机构（CA）包验证服务器的SSL证书。如果证书链无法被验证——因为CA包缺失、过时，或代理正在注入自己的证书——pip会拒绝连接以保护你免受中间人攻击。

### 常见原因

| 原因 | 症状 | 修复方法 |
|------|------|----------|
| **企业代理/防火墙** | 所有通过HTTPS的pip安装均失败 | 将企业CA证书添加到certifi包 |
| **Python版本过旧** | 旧的CA包无法验证现代证书 | 升级Python和certifi |
| **macOS全新安装** | Python已安装但证书未初始化 | 运行 `Install Certificates.command` |
| **Windows杀毒软件** | 杀毒软件拦截HTTPS流量 | 添加杀毒软件CA证书或将pip加入白名单 |
| **Conda环境** | Conda自带OpenSSL/证书 | `conda install certifi` 或设置 `SSL_CERT_FILE` |

### `--trusted-host` 参数说明

使用 `--trusted-host` 告诉pip跳过对该特定主机的证书验证。它**不会**完全禁用SSL——连接仍然是加密的，pip只是不验证通信对象的身份。这在开发机器上是可以接受的，但不应在供应链安全至关重要的CI/CD流水线或生产环境中使用。

---

## 相关资源

保护你的Python脚本并正确自动化安全任务。查看[Python安全脚本速查表](/cheatsheets/python-security-scripts/)——涵盖socket编程、Scapy以及使用 `requests` 库进行HTTP请求。
