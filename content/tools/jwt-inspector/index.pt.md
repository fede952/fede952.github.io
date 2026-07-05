---
title: "TokenLens: Decodificador JWT, Depurador e Verificador de Assinatura"
description: "Decodifique e depure qualquer JSON Web Token no navegador e verifique a assinatura (HS/RS/ES/PS) com a Web Crypto API. 100% no lado do cliente — nenhum token sai do seu dispositivo."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["decodificador jwt", "depurar jwt", "verificar assinatura jwt", "json web token", "validador jwt", "decodificar jwt online", "rs256", "es256", "hs256", "jwt lado cliente"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — Decodificador JWT e Verificador de Assinatura", "description": "Decodificador JWT gratuito no lado do cliente, depurador de claims e verificador de assinatura Web Crypto para algoritmos HS, RS, ES e PS.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## O que o TokenLens faz

O TokenLens decodifica qualquer JSON Web Token diretamente no navegador e apresenta o header, o payload e cada claim registrado em linguagem clara — issuer, subject, audience e a hora local exata em que o token foi emitido, torna-se válido ou expira. Depois você pode **verificar criptograficamente a assinatura** com a Web Crypto API usando o seu próprio segredo ou chave pública.

Ao contrário dos decodificadores do lado do servidor, o token nunca sai desta página: sem upload, sem logs, sem requisição de rede. É exatamente o que você precisa quando um token carrega claims de produção ou dados pessoais e colá-lo no servidor de terceiros não é uma opção.

## Algoritmos suportados

- **HMAC** — HS256, HS384, HS512 (verifica com um segredo compartilhado)
- **RSA** — RS256/384/512 e PS256/384/512 (verifica com chave pública PEM ou JWK)
- **ECDSA** — ES256, ES384, ES512 (verifica com chave pública EC ou JWK)

Cole um token para começar ou carregue o exemplo para ver uma assinatura HS256 verificada.
