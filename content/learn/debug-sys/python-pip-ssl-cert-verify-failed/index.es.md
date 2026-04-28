---
title: "SOLUCIÓN: pip install - SSL: CERTIFICATE_VERIFY_FAILED"
description: "Soluciona el error pip SSL CERTIFICATE_VERIFY_FAILED causado por proxies corporativos, certificados faltantes o instalaciones de Python desactualizadas. Múltiples soluciones incluidas."
date: 2026-02-11
tags: ["python", "debug", "pip", "ssl"]
keywords: ["pip ssl certificate verify failed", "pip install ssl error", "certificate verify failed python", "pip trusted host", "pip ssl error fix", "python ssl certificate", "pip corporate proxy", "pip install behind firewall", "pip certificate error windows", "pip ssl module not available"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SOLUCIÓN: pip install - SSL: CERTIFICATE_VERIFY_FAILED",
    "description": "Cómo solucionar el error SSL CERTIFICATE_VERIFY_FAILED de pip en Windows, Linux y macOS.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "es"
  }
---

## El Error

Ejecutas `pip install` y obtienes uno de estos errores:

```
ERROR: Could not fetch URL https://pypi.org/simple/requests/:
There was a problem confirming the ssl certificate:
  SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
  certificate verify failed: unable to get local issuer certificate'))
```

O una variante más corta:

```
pip is configured with locations that require TLS/SSL,
however the ssl module in Python is not available.
```

La descarga del paquete falla porque pip no puede verificar el certificado SSL de PyPI (el registro de paquetes de Python). Esto casi siempre es causado por un proxy corporativo que intercepta el tráfico HTTPS, certificados del sistema faltantes o una instalación de Python/pip desactualizada.

---

## La Solución Rápida

### Solución 1: Omitir la verificación SSL (solución inmediata)

Indica a pip que confíe en los hosts de PyPI sin verificación de certificado:

```bash
# Install a package bypassing SSL checks
pip install requests --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
```

Para hacer esto permanente, agrégalo a tu configuración de pip:

```bash
# Linux/macOS: Create or edit ~/.pip/pip.conf
# Windows: Create or edit %APPDATA%\pip\pip.ini

[global]
trusted-host =
    pypi.org
    pypi.python.org
    files.pythonhosted.org
```

### Solución 2: Actualizar certificados (solución correcta)

La verdadera solución es asegurarte de que tu sistema tenga certificados CA actualizados:

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

### Solución 3: Certificado del proxy corporativo

Si estás detrás de un proxy corporativo que intercepta HTTPS (MITM), necesitas agregar el certificado CA de tu empresa al almacén de confianza de Python:

```bash
# Find where certifi stores its CA bundle
python -c "import certifi; print(certifi.where())"

# Append your corporate CA certificate to that file
cat corporate-ca.crt >> $(python -c "import certifi; print(certifi.where())")
```

O establece la variable de entorno para apuntar a tu bundle CA personalizado:

```bash
# Linux/macOS
export PIP_CERT=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Windows (PowerShell)
$env:PIP_CERT = "C:\path\to\corporate-ca-bundle.crt"
$env:REQUESTS_CA_BUNDLE = "C:\path\to\corporate-ca-bundle.crt"
```

---

## La Explicación

Cuando pip se conecta a `https://pypi.org`, realiza un handshake TLS y verifica el certificado SSL del servidor contra un bundle de Autoridades de Certificación (CAs) de confianza. Si la cadena de certificados no puede ser validada — porque el bundle CA falta, está desactualizado, o un proxy está inyectando su propio certificado — pip rechaza la conexión para protegerte de ataques man-in-the-middle.

### Causas comunes

| Causa | Síntoma | Solución |
|-------|---------|----------|
| **Proxy/firewall corporativo** | Todas las instalaciones pip por HTTPS fallan | Agrega el certificado CA corporativo al bundle de certifi |
| **Python desactualizado** | El bundle CA antiguo no puede verificar certificados modernos | Actualiza Python y certifi |
| **Instalación nueva de macOS** | Python instalado pero certificados no inicializados | Ejecuta `Install Certificates.command` |
| **Antivirus en Windows** | El software AV intercepta el tráfico HTTPS | Agrega el certificado CA del AV o incluye pip en la lista blanca |
| **Entorno Conda** | Conda incluye su propio OpenSSL/certificados | `conda install certifi` o establece `SSL_CERT_FILE` |

### El flag `--trusted-host` explicado

Usar `--trusted-host` le indica a pip que omita la verificación de certificado para ese host específico. **No** desactiva SSL por completo — la conexión sigue estando cifrada, pip simplemente no verifica con quién se está comunicando. Esto es aceptable para máquinas de desarrollo, pero no debería usarse en pipelines CI/CD o entornos de producción donde la seguridad de la cadena de suministro es importante.

---

## Recursos Relacionados

Protege tus scripts de Python y automatiza correctamente las tareas de seguridad. Consulta el [Cheatsheet de Scripting de Seguridad en Python](/cheatsheets/python-security-scripts/) — que cubre programación con sockets, Scapy y peticiones HTTP con la librería `requests`.
