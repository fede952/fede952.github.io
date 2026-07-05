---
title: "TokenLens: Decodificador JWT, Depurador y Verificador de Firma"
description: "Decodifica y depura cualquier JSON Web Token en tu navegador y verifica su firma (HS/RS/ES/PS) con la Web Crypto API. 100% del lado del cliente: ningún token sale de tu dispositivo."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["decodificador jwt", "depurar jwt", "verificar firma jwt", "json web token", "validador jwt", "decodificar jwt online", "rs256", "es256", "hs256", "jwt lado cliente"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — Decodificador JWT y Verificador de Firma", "description": "Decodificador JWT gratuito del lado del cliente, depurador de claims y verificador de firma con Web Crypto para algoritmos HS, RS, ES y PS.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Qué hace TokenLens

TokenLens decodifica cualquier JSON Web Token directamente en tu navegador y muestra el header, el payload y cada claim registrado en lenguaje claro — issuer, subject, audience y la hora local exacta en que el token se emitió, se vuelve válido o expira. Luego puedes **verificar criptográficamente la firma** con la Web Crypto API usando tu propio secreto o clave pública.

A diferencia de los decodificadores del lado del servidor, el token nunca sale de esta página: sin subidas, sin registros, sin peticiones de red. Es justo lo que necesitas cuando un token lleva claims de producción o datos personales y pegarlo en el servidor de otra persona no es una opción.

## Algoritmos compatibles

- **HMAC** — HS256, HS384, HS512 (verifica con un secreto compartido)
- **RSA** — RS256/384/512 y PS256/384/512 (verifica con clave pública PEM o JWK)
- **ECDSA** — ES256, ES384, ES512 (verifica con clave pública EC o JWK)

Pega un token para empezar, o carga el ejemplo para ver una firma HS256 verificada.
