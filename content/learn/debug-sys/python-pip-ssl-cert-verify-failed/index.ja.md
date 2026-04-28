---
title: "修正: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "企業プロキシ、証明書の欠落、またはPythonの古いインストールが原因で発生するpip SSL CERTIFICATE_VERIFY_FAILEDエラーを修正します。複数の解決策を掲載。"
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "修正: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Windows、Linux、macOSでpipのSSL CERTIFICATE_VERIFY_FAILEDエラーを修正する方法。",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ja"
  }
---

## エラー内容

`pip install` を実行すると、以下のいずれかのエラーが表示されます：

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

または、より短いバリエーション：

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

pipがPyPI（Pythonのパッケージレジストリ）のSSL証明書を検証できないため、パッケージのダウンロードが失敗します。これはほぼ常に、HTTPSトラフィックを傍受する企業プロキシ、システム証明書の欠落、またはPython/pipの古いインストールが原因です。

---

## クイックフィックス

### 修正 1: SSL検証をバイパスする（即時の回避策）

証明書の検証なしでPyPIホストを信頼するようpipに指示します：

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

これを永続的にするには、pip設定に追加します：

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### 修正 2: 証明書を更新する（適切な修正）

本当の解決策は、システムに最新のCA証明書があることを確認することです：

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

### 修正 3: 企業プロキシの証明書

HTTPSを傍受する企業プロキシ（MITM）の背後にいる場合、会社のCA証明書をPythonの信頼ストアに追加する必要があります：

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

または、カスタムCAバンドルを指す環境変数を設定します：

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## 解説

pipが `https://pypi.org` に接続する際、TLSハンドシェイクを実行し、信頼された認証局（CA）のバンドルに対してサーバーのSSL証明書を検証します。証明書チェーンが検証できない場合 — CAバンドルが欠落している、古い、またはプロキシが独自の証明書を注入しているため — pipは中間者攻撃から保護するために接続を拒否します。

### よくある原因

| 原因 | 症状 | 修正方法 |
|------|------|----------|
| **企業プロキシ/ファイアウォール** | すべてのHTTPS経由のpipインストールが失敗する | 企業CA証明書をcertifiバンドルに追加 |
| **古いPython** | 古いCAバンドルが最新の証明書を検証できない | Pythonとcertifiを更新 |
| **macOSの新規インストール** | Pythonはインストール済みだが証明書が初期化されていない | `Install Certificates.command` を実行 |
| **Windowsアンチウイルス** | AVソフトウェアがHTTPSトラフィックを傍受 | AVのCA証明書を追加するかpipをホワイトリストに追加 |
| **Conda環境** | Condaが独自のOpenSSL/証明書を同梱 | `conda install certifi` または `SSL_CERT_FILE` を設定 |

### `--trusted-host` フラグの説明

`--trusted-host` を使用すると、その特定のホストに対する証明書の検証をスキップするようpipに指示します。SSLを完全に無効にするわけでは**ありません** — 接続は暗号化されたまま、pipは通信相手を検証しないだけです。開発マシンでは許容されますが、サプライチェーンセキュリティが重要なCI/CDパイプラインや本番環境では使用すべきではありません。

---

## 関連リソース

Pythonスクリプトを保護し、セキュリティタスクを適切に自動化しましょう。[Pythonセキュリティスクリプティング チートシート](/cheatsheets/python-security-scripts/)をご覧ください — ソケットプログラミング、Scapy、`requests`ライブラリを使用したHTTPリクエストを解説しています。
