---
title: "CORREÇÃO: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Corrija o erro pip SSL CERTIFICATE_VERIFY_FAILED causado por proxies corporativos, certificados ausentes ou instalações Python desatualizadas. Múltiplas soluções incluídas."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CORREÇÃO: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Como corrigir o erro SSL CERTIFICATE_VERIFY_FAILED do pip no Windows, Linux e macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "pt"
  }
---

## O Erro

Você executa `pip install` e recebe um destes erros:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

Ou uma variante mais curta:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

O download do pacote falha porque o pip não consegue verificar o certificado SSL do PyPI (o registro de pacotes do Python). Isso quase sempre é causado por um proxy corporativo interceptando o tráfego HTTPS, certificados de sistema ausentes ou uma instalação desatualizada do Python/pip.

---

## A Correção Rápida

### Correção 1: Ignorar a verificação SSL (solução imediata)

Diga ao pip para confiar nos hosts do PyPI sem verificação de certificado:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

Para tornar isso permanente, adicione à sua configuração do pip:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Correção 2: Atualizar certificados (correção adequada)

A verdadeira solução é garantir que seu sistema tenha certificados CA atualizados:

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

### Correção 3: Certificado do proxy corporativo

Se você está atrás de um proxy corporativo que intercepta HTTPS (MITM), você precisa adicionar o certificado CA da sua empresa ao armazenamento de confiança do Python:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

Ou defina a variável de ambiente para apontar para seu bundle CA personalizado:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## A Explicação

Quando o pip se conecta a `https://pypi.org`, ele realiza um handshake TLS e verifica o certificado SSL do servidor contra um bundle de Autoridades Certificadoras (CAs) confiáveis. Se a cadeia de certificados não puder ser validada — porque o bundle CA está ausente, desatualizado, ou um proxy está injetando seu próprio certificado — o pip recusa a conexão para protegê-lo de ataques man-in-the-middle.

### Causas comuns

| Causa | Sintoma | Correção |
|-------|---------|----------|
| **Proxy/firewall corporativo** | Todas as instalações pip via HTTPS falham | Adicione o certificado CA corporativo ao bundle certifi |
| **Python desatualizado** | Bundle CA antigo não consegue verificar certificados modernos | Atualize Python e certifi |
| **Instalação nova do macOS** | Python instalado mas certificados não inicializados | Execute `Install Certificates.command` |
| **Antivírus Windows** | Software AV intercepta o tráfego HTTPS | Adicione o certificado CA do AV ou coloque o pip na lista branca |
| **Ambiente Conda** | Conda inclui seu próprio OpenSSL/certificados | `conda install certifi` ou defina `SSL_CERT_FILE` |

### O flag `--trusted-host` explicado

Usar `--trusted-host` diz ao pip para pular a verificação de certificado para aquele host específico. Isso **não** desativa o SSL completamente — a conexão continua criptografada, o pip apenas não verifica com quem está se comunicando. Isso é aceitável para máquinas de desenvolvimento, mas não deve ser usado em pipelines CI/CD ou ambientes de produção onde a segurança da cadeia de suprimentos é importante.

---

## Recursos Relacionados

Proteja seus scripts Python e automatize tarefas de segurança corretamente. Confira o [Cheatsheet de Scripting de Segurança Python](/cheatsheets/python-security-scripts/) — cobrindo programação com sockets, Scapy e requisições HTTP com a biblioteca `requests`.
