---
title: "LÖSUNG: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Beheben Sie den pip SSL CERTIFICATE_VERIFY_FAILED Fehler, verursacht durch Firmen-Proxys, fehlende Zertifikate oder veraltete Python-Installationen. Mehrere Lösungen enthalten."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "LÖSUNG: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "So beheben Sie den SSL CERTIFICATE_VERIFY_FAILED Fehler von pip unter Windows, Linux und macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "de"
  }
---

## Der Fehler

Sie führen `pip install` aus und erhalten einen dieser Fehler:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

Oder eine kürzere Variante:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

Der Paket-Download schlägt fehl, weil pip das SSL-Zertifikat von PyPI (Pythons Paketregister) nicht verifizieren kann. Dies wird fast immer durch einen Firmen-Proxy verursacht, der HTTPS-Verkehr abfängt, fehlende Systemzertifikate oder eine veraltete Python/pip-Installation.

---

## Die Schnelle Lösung

### Lösung 1: SSL-Verifizierung umgehen (sofortige Umgehung)

Weisen Sie pip an, den PyPI-Hosts ohne Zertifikatsverifizierung zu vertrauen:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

Um dies dauerhaft zu machen, fügen Sie es Ihrer pip-Konfiguration hinzu:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Lösung 2: Zertifikate aktualisieren (richtige Lösung)

Die eigentliche Lösung besteht darin, sicherzustellen, dass Ihr System über aktuelle CA-Zertifikate verfügt:

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

### Lösung 3: Firmen-Proxy-Zertifikat

Wenn Sie sich hinter einem Firmen-Proxy befinden, der HTTPS abfängt (MITM), müssen Sie das CA-Zertifikat Ihres Unternehmens zum Vertrauensspeicher von Python hinzufügen:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

Oder setzen Sie die Umgebungsvariable, um auf Ihr benutzerdefiniertes CA-Bundle zu verweisen:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## Die Erklärung

Wenn pip sich mit `https://pypi.org` verbindet, führt es einen TLS-Handshake durch und überprüft das SSL-Zertifikat des Servers gegen ein Bundle vertrauenswürdiger Zertifizierungsstellen (CAs). Wenn die Zertifikatskette nicht validiert werden kann — weil das CA-Bundle fehlt, veraltet ist oder ein Proxy sein eigenes Zertifikat einschleust — verweigert pip die Verbindung, um Sie vor Man-in-the-Middle-Angriffen zu schützen.

### Häufige Ursachen

| Ursache | Symptom | Lösung |
|---------|---------|--------|
| **Firmen-Proxy/Firewall** | Alle HTTPS-pip-Installationen schlagen fehl | Firmen-CA-Zertifikat zum certifi-Bundle hinzufügen |
| **Veraltetes Python** | Altes CA-Bundle kann moderne Zertifikate nicht verifizieren | Python und certifi aktualisieren |
| **Frische macOS-Installation** | Python installiert, aber Zertifikate nicht initialisiert | `Install Certificates.command` ausführen |
| **Windows-Antivirus** | AV-Software fängt HTTPS-Verkehr ab | AV-CA-Zertifikat hinzufügen oder pip auf die Whitelist setzen |
| **Conda-Umgebung** | Conda liefert eigenes OpenSSL/Zertifikate mit | `conda install certifi` oder `SSL_CERT_FILE` setzen |

### Das `--trusted-host` Flag erklärt

Die Verwendung von `--trusted-host` weist pip an, die Zertifikatsverifizierung für diesen bestimmten Host zu überspringen. Es deaktiviert SSL **nicht** vollständig — die Verbindung bleibt verschlüsselt, pip überprüft nur nicht, mit wem es kommuniziert. Dies ist für Entwicklungsmaschinen akzeptabel, sollte aber nicht in CI/CD-Pipelines oder Produktionsumgebungen verwendet werden, wo die Sicherheit der Lieferkette wichtig ist.

---

## Verwandte Ressourcen

Sichern Sie Ihre Python-Skripte ab und automatisieren Sie Sicherheitsaufgaben richtig. Schauen Sie sich das [Python Security Scripting Cheatsheet](/cheatsheets/python-security-scripts/) an — es behandelt Socket-Programmierung, Scapy und HTTP-Anfragen mit der `requests`-Bibliothek.
