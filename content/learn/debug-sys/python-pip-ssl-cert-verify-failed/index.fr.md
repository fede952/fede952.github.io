---
title: "CORRECTIF: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Corrigez l'erreur pip SSL CERTIFICATE_VERIFY_FAILED causée par des proxies d'entreprise, des certificats manquants ou des installations Python obsolètes. Plusieurs solutions incluses."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CORRECTIF: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Comment corriger l'erreur SSL CERTIFICATE_VERIFY_FAILED de pip sous Windows, Linux et macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "fr"
  }
---

## L'Erreur

Vous exécutez `pip install` et obtenez l'une de ces erreurs :

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

Ou une variante plus courte :

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

Le téléchargement du paquet échoue parce que pip ne peut pas vérifier le certificat SSL de PyPI (le registre de paquets Python). Cela est presque toujours causé par un proxy d'entreprise interceptant le trafic HTTPS, des certificats système manquants ou une installation Python/pip obsolète.

---

## La Solution Rapide

### Correctif 1 : Contourner la vérification SSL (solution de contournement immédiate)

Indiquez à pip de faire confiance aux hôtes PyPI sans vérification de certificat :

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

Pour rendre cela permanent, ajoutez-le à votre configuration pip :

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Correctif 2 : Mettre à jour les certificats (solution appropriée)

La vraie solution est de s'assurer que votre système dispose de certificats CA à jour :

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

### Correctif 3 : Certificat du proxy d'entreprise

Si vous êtes derrière un proxy d'entreprise qui intercepte le HTTPS (MITM), vous devez ajouter le certificat CA de votre entreprise au magasin de confiance de Python :

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

Ou définissez la variable d'environnement pour pointer vers votre bundle CA personnalisé :

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## L'Explication

Lorsque pip se connecte à `https://pypi.org`, il effectue une négociation TLS et vérifie le certificat SSL du serveur par rapport à un bundle d'Autorités de Certification (CA) de confiance. Si la chaîne de certificats ne peut pas être validée — parce que le bundle CA est manquant, obsolète, ou qu'un proxy injecte son propre certificat — pip refuse la connexion pour vous protéger des attaques de type man-in-the-middle.

### Causes courantes

| Cause | Symptôme | Correctif |
|-------|----------|-----------|
| **Proxy/pare-feu d'entreprise** | Toutes les installations pip via HTTPS échouent | Ajoutez le certificat CA d'entreprise au bundle certifi |
| **Python obsolète** | L'ancien bundle CA ne peut pas vérifier les certificats modernes | Mettez à jour Python et certifi |
| **Nouvelle installation macOS** | Python installé mais certificats non initialisés | Exécutez `Install Certificates.command` |
| **Antivirus Windows** | Le logiciel AV intercepte le trafic HTTPS | Ajoutez le certificat CA de l'AV ou ajoutez pip à la liste blanche |
| **Environnement Conda** | Conda embarque son propre OpenSSL/certificats | `conda install certifi` ou définissez `SSL_CERT_FILE` |

### Le flag `--trusted-host` expliqué

Utiliser `--trusted-host` indique à pip de ne pas vérifier le certificat pour cet hôte spécifique. Cela ne désactive **pas** SSL entièrement — la connexion reste chiffrée, pip ne vérifie simplement pas l'identité de son interlocuteur. C'est acceptable pour les machines de développement, mais ne devrait pas être utilisé dans les pipelines CI/CD ou les environnements de production où la sécurité de la chaîne d'approvisionnement est importante.

---

## Ressources Associées

Sécurisez vos scripts Python et automatisez correctement les tâches de sécurité. Consultez le [Cheatsheet de Scripting de Sécurité Python](/cheatsheets/python-security-scripts/) — couvrant la programmation réseau avec les sockets, Scapy et les requêtes HTTP avec la bibliothèque `requests`.
