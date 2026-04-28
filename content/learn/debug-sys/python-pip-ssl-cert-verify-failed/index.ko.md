---
title: "수정: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "기업 프록시, 누락된 인증서 또는 오래된 Python 설치로 인한 pip SSL CERTIFICATE_VERIFY_FAILED 오류를 수정합니다. 여러 가지 해결 방법이 포함되어 있습니다."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "수정: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Windows, Linux, macOS에서 pip의 SSL CERTIFICATE_VERIFY_FAILED 오류를 수정하는 방법.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ko"
  }
---

## 오류 내용

`pip install`을 실행하면 다음 오류 중 하나가 발생합니다:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

또는 더 짧은 변형:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

pip가 PyPI(Python 패키지 레지스트리)의 SSL 인증서를 확인할 수 없기 때문에 패키지 다운로드가 실패합니다. 이는 거의 항상 HTTPS 트래픽을 가로채는 기업 프록시, 누락된 시스템 인증서 또는 오래된 Python/pip 설치가 원인입니다.

---

## 빠른 수정

### 수정 1: SSL 검증 우회 (즉각적인 해결 방법)

인증서 검증 없이 PyPI 호스트를 신뢰하도록 pip에 지시합니다:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

이를 영구적으로 적용하려면 pip 설정에 추가합니다:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### 수정 2: 인증서 업데이트 (올바른 수정)

진정한 해결책은 시스템에 최신 CA 인증서가 있는지 확인하는 것입니다:

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

### 수정 3: 기업 프록시 인증서

HTTPS를 가로채는 기업 프록시(MITM) 뒤에 있는 경우, 회사의 CA 인증서를 Python의 신뢰 저장소에 추가해야 합니다:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

또는 사용자 정의 CA 번들을 가리키는 환경 변수를 설정합니다:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## 설명

pip가 `https://pypi.org`에 연결할 때 TLS 핸드셰이크를 수행하고 신뢰할 수 있는 인증 기관(CA) 번들에 대해 서버의 SSL 인증서를 검증합니다. 인증서 체인을 검증할 수 없는 경우 — CA 번들이 누락되었거나, 오래되었거나, 프록시가 자체 인증서를 주입하고 있기 때문에 — pip는 중간자 공격으로부터 보호하기 위해 연결을 거부합니다.

### 일반적인 원인

| 원인 | 증상 | 수정 방법 |
|------|------|-----------|
| **기업 프록시/방화벽** | 모든 HTTPS pip 설치가 실패함 | 기업 CA 인증서를 certifi 번들에 추가 |
| **오래된 Python** | 이전 CA 번들이 최신 인증서를 검증할 수 없음 | Python과 certifi 업데이트 |
| **macOS 새로 설치** | Python이 설치되었지만 인증서가 초기화되지 않음 | `Install Certificates.command` 실행 |
| **Windows 안티바이러스** | AV 소프트웨어가 HTTPS 트래픽을 가로챔 | AV CA 인증서 추가 또는 pip를 화이트리스트에 추가 |
| **Conda 환경** | Conda가 자체 OpenSSL/인증서를 포함 | `conda install certifi` 또는 `SSL_CERT_FILE` 설정 |

### `--trusted-host` 플래그 설명

`--trusted-host`를 사용하면 해당 특정 호스트에 대한 인증서 검증을 건너뛰도록 pip에 지시합니다. SSL을 완전히 비활성화하는 것은 **아닙니다** — 연결은 여전히 암호화되며, pip가 통신 상대를 확인하지 않을 뿐입니다. 개발 머신에서는 허용되지만 공급망 보안이 중요한 CI/CD 파이프라인이나 프로덕션 환경에서는 사용하지 않아야 합니다.

---

## 관련 리소스

Python 스크립트를 보호하고 보안 작업을 올바르게 자동화하세요. [Python 보안 스크립팅 치트시트](/cheatsheets/python-security-scripts/)를 확인하세요 — 소켓 프로그래밍, Scapy, `requests` 라이브러리를 사용한 HTTP 요청을 다루고 있습니다.
