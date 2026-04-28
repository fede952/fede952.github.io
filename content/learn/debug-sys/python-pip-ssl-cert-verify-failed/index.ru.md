---
title: "ИСПРАВЛЕНИЕ: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Исправьте ошибку pip SSL CERTIFICATE_VERIFY_FAILED, вызванную корпоративными прокси, отсутствующими сертификатами или устаревшими установками Python. Несколько решений включено."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "ИСПРАВЛЕНИЕ: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Как исправить ошибку SSL CERTIFICATE_VERIFY_FAILED в pip на Windows, Linux и macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ru"
  }
---

## Ошибка

Вы запускаете `pip install` и получаете одну из этих ошибок:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

Или более короткий вариант:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

Загрузка пакета завершается неудачей, потому что pip не может проверить SSL-сертификат PyPI (реестра пакетов Python). Почти всегда это вызвано корпоративным прокси, перехватывающим HTTPS-трафик, отсутствующими системными сертификатами или устаревшей установкой Python/pip.

---

## Быстрое Исправление

### Исправление 1: Обход проверки SSL (немедленный обходной путь)

Укажите pip доверять хостам PyPI без проверки сертификата:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

Чтобы сделать это постоянным, добавьте в конфигурацию pip:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Исправление 2: Обновление сертификатов (правильное решение)

Настоящее решение — убедиться, что в вашей системе есть актуальные сертификаты CA:

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

### Исправление 3: Сертификат корпоративного прокси

Если вы находитесь за корпоративным прокси, перехватывающим HTTPS (MITM), вам нужно добавить CA-сертификат вашей компании в хранилище доверия Python:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

Или задайте переменную окружения, указывающую на ваш пользовательский CA-бандл:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## Объяснение

Когда pip подключается к `https://pypi.org`, он выполняет TLS-рукопожатие и проверяет SSL-сертификат сервера по набору доверенных Центров Сертификации (CA). Если цепочка сертификатов не может быть проверена — из-за отсутствия CA-бандла, его устаревания или внедрения прокси собственного сертификата — pip отклоняет соединение для защиты от атак типа «человек посередине».

### Распространённые причины

| Причина | Симптом | Решение |
|---------|---------|---------|
| **Корпоративный прокси/файрвол** | Все установки pip через HTTPS завершаются ошибкой | Добавьте корпоративный CA-сертификат в бандл certifi |
| **Устаревший Python** | Старый CA-бандл не может проверить современные сертификаты | Обновите Python и certifi |
| **Свежая установка macOS** | Python установлен, но сертификаты не инициализированы | Запустите `Install Certificates.command` |
| **Антивирус Windows** | Антивирус перехватывает HTTPS-трафик | Добавьте CA-сертификат антивируса или внесите pip в белый список |
| **Среда Conda** | Conda поставляется со своим OpenSSL/сертификатами | `conda install certifi` или задайте `SSL_CERT_FILE` |

### Флаг `--trusted-host` подробнее

Использование `--trusted-host` указывает pip пропустить проверку сертификата для конкретного хоста. Это **не** отключает SSL полностью — соединение остаётся зашифрованным, pip просто не проверяет, с кем он общается. Это допустимо для машин разработки, но не должно использоваться в CI/CD-пайплайнах или продакшн-средах, где безопасность цепочки поставок имеет значение.

---

## Связанные Ресурсы

Защитите свои Python-скрипты и правильно автоматизируйте задачи безопасности. Ознакомьтесь с [Шпаргалкой по Python-скриптам безопасности](/cheatsheets/python-security-scripts/) — охватывающей программирование сокетов, Scapy и HTTP-запросы с библиотекой `requests`.
