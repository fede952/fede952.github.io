---
title: "TokenLens: JWT-Decoder, Debugger & Signaturprüfer"
description: "Dekodiere und debugge jeden JSON Web Token im Browser und verifiziere seine Signatur (HS/RS/ES/PS) mit der Web Crypto API. 100% clientseitig — kein Token verlässt dein Gerät."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["jwt decoder", "jwt debuggen", "jwt signatur prüfen", "json web token", "jwt validator", "jwt online dekodieren", "rs256", "es256", "hs256", "clientseitiges jwt"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — JWT-Decoder & Signaturprüfer", "description": "Kostenloser clientseitiger JWT-Decoder, Claims-Debugger und Web-Crypto-Signaturprüfer für HS-, RS-, ES- und PS-Algorithmen.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Was TokenLens macht

TokenLens dekodiert jeden JSON Web Token direkt im Browser und zeigt Header, Payload und jeden registrierten Claim in verständlicher Sprache — Issuer, Subject, Audience und die exakte lokale Zeit, zu der ein Token ausgestellt wurde, gültig wird oder abläuft. Anschließend kannst du die **Signatur kryptografisch verifizieren** — mit der Web Crypto API und deinem eigenen Secret oder öffentlichen Schlüssel.

Anders als serverbasierte Decoder verlässt der Token diese Seite nie: kein Upload, kein Logging, keine Netzwerkanfrage. Genau das brauchst du, wenn ein Token Produktions-Claims oder personenbezogene Daten enthält und das Einfügen in einen fremden Server keine Option ist.

## Unterstützte Algorithmen

- **HMAC** — HS256, HS384, HS512 (Prüfung mit gemeinsamem Secret)
- **RSA** — RS256/384/512 und PS256/384/512 (Prüfung mit PEM-Public-Key oder JWK)
- **ECDSA** — ES256, ES384, ES512 (Prüfung mit EC-Public-Key oder JWK)

Füge einen Token ein, um zu starten, oder lade das Beispiel für eine verifizierte HS256-Signatur.
