---
title: "SOLUZIONE: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Risolvi l'errore pip SSL CERTIFICATE_VERIFY_FAILED causato da proxy aziendali, certificati mancanti o installazioni Python obsolete. Soluzioni multiple incluse."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SOLUZIONE: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Come risolvere l'errore SSL CERTIFICATE_VERIFY_FAILED di pip su Windows, Linux e macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "it"
  }
---

## L'Errore

Esegui `pip install` e ottieni uno di questi errori:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

Oppure una variante più breve:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

Il download del pacchetto fallisce perché pip non riesce a verificare il certificato SSL di PyPI (il registro dei pacchetti Python). Nella quasi totalità dei casi, la causa è un proxy aziendale che intercetta il traffico HTTPS, certificati di sistema mancanti o un'installazione Python/pip obsoleta.

---

## La Soluzione Rapida

### Soluzione 1: Bypassare la verifica SSL (workaround immediato)

Indica a pip di fidarsi degli host PyPI senza verifica del certificato:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

Per rendere questa impostazione permanente, aggiungila alla configurazione di pip:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Soluzione 2: Aggiornare i certificati (soluzione corretta)

La vera soluzione è assicurarsi che il sistema disponga di certificati CA aggiornati:

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

### Soluzione 3: Certificato del proxy aziendale

Se ti trovi dietro un proxy aziendale che intercetta il traffico HTTPS (MITM), devi aggiungere il certificato CA della tua azienda al trust store di Python:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

Oppure imposta la variabile d'ambiente per puntare al tuo bundle CA personalizzato:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## La Spiegazione

Quando pip si connette a `https://pypi.org`, esegue un handshake TLS e verifica il certificato SSL del server rispetto a un bundle di Autorità di Certificazione (CA) attendibili. Se la catena di certificati non può essere validata — perché il bundle CA è mancante, obsoleto, o un proxy sta iniettando il proprio certificato — pip rifiuta la connessione per proteggerti da attacchi man-in-the-middle.

### Cause comuni

| Causa | Sintomo | Soluzione |
|-------|---------|-----------|
| **Proxy/firewall aziendale** | Tutte le installazioni pip via HTTPS falliscono | Aggiungi il certificato CA aziendale al bundle certifi |
| **Python obsoleto** | Il bundle CA vecchio non riesce a verificare i certificati moderni | Aggiorna Python e certifi |
| **Nuova installazione macOS** | Python installato ma certificati non inizializzati | Esegui `Install Certificates.command` |
| **Antivirus Windows** | Il software AV intercetta il traffico HTTPS | Aggiungi il certificato CA dell'AV o inserisci pip nella whitelist |
| **Ambiente Conda** | Conda include il proprio OpenSSL/certificati | `conda install certifi` oppure imposta `SSL_CERT_FILE` |

### Il flag `--trusted-host` spiegato

Usare `--trusted-host` indica a pip di saltare la verifica del certificato per quell'host specifico. **Non** disabilita completamente SSL — la connessione resta crittografata, ma pip non verifica con chi sta comunicando. Questo è accettabile per le macchine di sviluppo, ma non dovrebbe essere usato in pipeline CI/CD o ambienti di produzione dove la sicurezza della supply chain è importante.

---

## Risorse Correlate

Proteggi i tuoi script Python e automatizza correttamente le attività di sicurezza. Consulta il [Cheatsheet di Scripting per la Sicurezza in Python](/cheatsheets/python-security-scripts/) — che copre la programmazione con socket, Scapy e le richieste HTTP con la libreria `requests`.
