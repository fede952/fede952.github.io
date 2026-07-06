---
title: "SafeEnv: Escáner de Secretos y Claves API para Archivos .env"
description: "Escanea tus archivos .env y fragmentos de configuración en busca de secretos expuestos antes de hacer commit — claves AWS, tokens de GitHub y Stripe, claves privadas, contraseñas en URLs y valores de alta entropía. 100% en tu navegador: nada se sube nunca."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["escáner archivo env", "escáner de secretos", "comprobar claves api", "detectar secretos expuestos", "escanear env", "fuga claves aws", "git secrets", "escáner de secretos lado cliente", "seguridad dotenv"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — Escáner de Secretos y Claves API", "description": "Escáner gratuito del lado del cliente que encuentra claves API, tokens, claves privadas y contraseñas expuestas en archivos .env y configuraciones antes del commit.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Por qué escanear antes del commit

Basta un `.env` pegado en un repo público: los bots rastrean GitHub y encuentran claves AWS recientes en **menos de un minuto**. SafeEnv detecta la fuga antes del commit. Pega cualquier configuración — `.env`, `docker-compose.yml`, config de CI, fragmentos de código — y marca las credenciales expuestas con número de línea, vista previa enmascarada y pasos concretos de remediación.

El escaneo se ejecuta por completo en la memoria de esta página. Sin subidas, sin registros, sin peticiones de red — el único diseño aceptable para una herramienta en la que pegas secretos reales. Recarga la página y todo desaparece.

## Qué detecta

- **Tokens de nube y API** — claves AWS, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **Claves privadas** — bloques PEM RSA/EC/OpenSSH/PGP
- **Credenciales en URLs** — cadenas de conexión a bases de datos y URLs basic-auth con contraseñas incrustadas
- **Fugas genéricas** — contraseñas hardcodeadas y valores de alta entropía, con detección de placeholders para reducir falsos positivos

Pega una configuración para escanearla, o carga el ejemplo para ver todos los detectores en acción con claves falsas.
