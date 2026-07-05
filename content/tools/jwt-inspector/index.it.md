---
title: "TokenLens: Decoder JWT, Debugger e Verifica Firma"
description: "Decodifica e analizza qualsiasi JSON Web Token nel browser, poi verifica crittograficamente la firma (HS/RS/ES/PS) con la Web Crypto API. 100% lato client — nessun token lascia il tuo dispositivo."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["decoder jwt", "debug jwt", "verifica firma jwt", "json web token", "validatore jwt", "decodificare jwt online", "rs256", "es256", "hs256", "jwt lato client"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — Decoder JWT e Verifica Firma", "description": "Decoder JWT gratuito e lato client, debugger dei claim e verifica della firma con Web Crypto per algoritmi HS, RS, ES e PS.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Cosa fa TokenLens

TokenLens decodifica qualsiasi JSON Web Token direttamente nel browser e mostra header, payload e ogni claim registrato in linguaggio chiaro — issuer, subject, audience e l'ora locale esatta in cui il token è stato emesso, diventa valido o scade. Poi puoi **verificare crittograficamente la firma** con la Web Crypto API usando il tuo segreto o la tua chiave pubblica.

A differenza dei decoder lato server, il token non lascia mai questa pagina: nessun upload, nessun log, nessuna richiesta di rete. È esattamente ciò che serve quando un token contiene claim di produzione o dati personali e incollarlo nel server di qualcun altro non è un'opzione.

## Algoritmi supportati

- **HMAC** — HS256, HS384, HS512 (verifica con un segreto condiviso)
- **RSA** — RS256/384/512 e PS256/384/512 (verifica con chiave pubblica PEM o JWK)
- **ECDSA** — ES256, ES384, ES512 (verifica con chiave pubblica EC o JWK)

Incolla un token per iniziare, oppure carica l'esempio per vedere una firma HS256 verificata.
