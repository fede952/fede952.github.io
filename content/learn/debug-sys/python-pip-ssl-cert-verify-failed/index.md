---
title: "FIX: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Fix the pip SSL CERTIFICATE_VERIFY_FAILED error caused by corporate proxies, missing certificates, or outdated Python installations. Multiple solutions included."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "FIX: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "How to fix pip's SSL CERTIFICATE_VERIFY_FAILED error on Windows, Linux, and macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "en"
  }
---

## The Error

You run `pip install` and get one of these errors:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

Or a shorter variant:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

The package download fails because pip cannot verify the SSL certificate of PyPI (Python's package registry). This is almost always caused by a corporate proxy intercepting HTTPS traffic, missing system certificates, or an outdated Python/pip installation.

---

## The Quick Fix

### Fix 1: Bypass SSL verification (immediate workaround)

Tell pip to trust PyPI hosts without certificate verification:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

To make this permanent, add it to your pip config:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Fix 2: Update certificates (proper fix)

The real solution is to ensure your system has up-to-date CA certificates:

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

### Fix 3: Corporate proxy certificate

If you are behind a corporate proxy that intercepts HTTPS (MITM), you need to add your company's CA certificate to Python's trust store:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

Or set the environment variable to point to your custom CA bundle:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## The Explanation

When pip connects to `https://pypi.org`, it performs a TLS handshake and verifies the server's SSL certificate against a bundle of trusted Certificate Authorities (CAs). If the certificate chain cannot be validated — because the CA bundle is missing, outdated, or a proxy is injecting its own certificate — pip refuses the connection to protect you from man-in-the-middle attacks.

### Common causes

| Cause | Symptom | Fix |
|-------|---------|-----|
| **Corporate proxy/firewall** | All HTTPS pip installs fail | Add corporate CA cert to certifi bundle |
| **Outdated Python** | Old CA bundle cannot verify modern certificates | Upgrade Python and certifi |
| **macOS fresh install** | Python installed but certificates not bootstrapped | Run `Install Certificates.command` |
| **Windows antivirus** | AV software intercepts HTTPS traffic | Add AV CA cert or whitelist pip |
| **Conda environment** | Conda ships its own OpenSSL/certs | `conda install certifi` or set `SSL_CERT_FILE` |

### The `--trusted-host` flag explained

Using `--trusted-host` tells pip to skip certificate verification for that specific host. It does **not** disable SSL entirely — the connection is still encrypted, pip just does not verify who it is talking to. This is acceptable for development machines but should not be used in CI/CD pipelines or production environments where supply-chain security matters.

---

## Related Resources

Secure your Python scripts and automate security tasks properly. Check the [Python Security Scripting Cheatsheet](/cheatsheets/python-security-scripts/) — covering socket programming, Scapy, and HTTP requests with the `requests` library.
