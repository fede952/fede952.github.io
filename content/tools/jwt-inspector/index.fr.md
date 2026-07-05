---
title: "TokenLens : Décodeur JWT, Débogueur et Vérificateur de Signature"
description: "Décodez et déboguez n'importe quel JSON Web Token dans votre navigateur, puis vérifiez sa signature (HS/RS/ES/PS) avec la Web Crypto API. 100% côté client — aucun token ne quitte votre appareil."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["décodeur jwt", "déboguer jwt", "vérifier signature jwt", "json web token", "validateur jwt", "décoder jwt en ligne", "rs256", "es256", "hs256", "jwt côté client"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — Décodeur JWT et Vérificateur de Signature", "description": "Décodeur JWT gratuit côté client, débogueur de claims et vérificateur de signature Web Crypto prenant en charge les algorithmes HS, RS, ES et PS.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Ce que fait TokenLens

TokenLens décode n'importe quel JSON Web Token directement dans votre navigateur et présente l'en-tête, la charge utile et chaque claim enregistré en langage clair — issuer, subject, audience et l'heure locale exacte à laquelle le token a été émis, devient valide ou expire. Vous pouvez ensuite **vérifier cryptographiquement la signature** avec la Web Crypto API à l'aide de votre propre secret ou clé publique.

Contrairement aux décodeurs côté serveur, le token ne quitte jamais cette page : aucun envoi, aucun journal, aucune requête réseau. C'est exactement ce qu'il vous faut lorsqu'un token contient des claims de production ou des données personnelles et que le coller sur le serveur d'un tiers n'est pas envisageable.

## Algorithmes pris en charge

- **HMAC** — HS256, HS384, HS512 (vérification avec un secret partagé)
- **RSA** — RS256/384/512 et PS256/384/512 (vérification avec clé publique PEM ou JWK)
- **ECDSA** — ES256, ES384, ES512 (vérification avec clé publique EC ou JWK)

Collez un token pour commencer, ou chargez l'exemple pour voir une signature HS256 vérifiée.
