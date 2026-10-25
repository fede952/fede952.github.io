---
title: "Decodificare JWT e Verificare la Firma"
description: "Decodifica qualsiasi JSON Web Token, leggi claim e scadenza e verifica firme HS256, RS256, PS256 o ES256 con la Web Crypto API, tutto nel browser."
intro: "Incolla un **JSON Web Token** per vederne header e payload, controllare `exp`, `nbf` e `iat` in orario leggibile e verificarne la firma con un segreto o una chiave pubblica. Decodifica e verifica avvengono nel tuo browser: il token non viene mai inviato."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["decodificare jwt", "jwt decoder", "verificare firma jwt", "jwt online", "verifica token jwt", "jwt rs256", "scadenza jwt", "jwt debugger"]
tags: ["sicurezza", "strumenti-sviluppo", "jwt", "strumento"]
app_category: "DeveloperApplication"
tool_file: "/tools/jwt-inspector/"
tool_title: "TokenLens: decoder JWT e verifica della firma"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-read; clipboard-write"
howto:
  - "Incolla un token nella casella o premi **Paste** per leggerlo dagli appunti. **Load sample** inserisce un token HS256 dimostrativo."
  - "Il token viene diviso nelle tre parti colorate e decodificato all'istante: header e payload compaiono come JSON evidenziato."
  - "Guarda i chip di stato: algoritmo, `typ`, `kid` e se il token è scaduto o non ancora valido. La tabella dei claim traduce `exp`, `nbf` e `iat` in date locali."
  - "Per verificare, incolla il **segreto HMAC** per HS256/384/512 (spunta *Secret is Base64URL-encoded* se lo è) oppure la **chiave pubblica** di chi firma, in PEM o JWK, per gli algoritmi RS, PS ed ES."
  - "Premi **Verify signature**. Verde significa che la firma corrisponde alla chiave e il token non è stato modificato; rosso significa chiave sbagliata o token alterato."
faq:
  - q: "È sicuro incollare qui un JWT di produzione?"
    a: "Lo strumento gira interamente nel browser e non fa richieste di rete con il token, quindi da parte nostra non viene registrato nulla. Ricorda però che un access token valido è una password con scadenza: chiunque lo veda può usarlo finché non scade. Meglio token scaduti o di test, e mai in uno strumento che non puoi ispezionare."
  - q: "Che differenza c'è tra decodificare e verificare un JWT?"
    a: "Decodificare significa solo invertire la codifica Base64URL di header e payload, e lo può fare chiunque: un JWT è firmato, non cifrato. Verificare significa ricalcolare la firma su `header.payload` con la chiave e controllare che coincida con il terzo segmento. Solo la verifica ti dice che il token è stato emesso da chi possiede la chiave e non è stato modificato."
  - q: "Quali algoritmi può verificare?"
    a: "HS256, HS384 e HS512 (HMAC con segreto condiviso); RS256, RS384 e RS512 (RSA PKCS#1 v1.5); PS256, PS384 e PS512 (RSA-PSS); ES256, ES384 ed ES512 (ECDSA su P-256, P-384 e P-521). I token con `alg: none` o altri algoritmi vengono decodificati ma non verificati."
  - q: "Dove trovo la chiave pubblica per un token RS256?"
    a: "La maggior parte dei provider di identità pubblica le chiavi come JWKS a un URL tipo `https://issuer/.well-known/jwks.json`. Trova la voce il cui `kid` corrisponde all'header del token e incolla quel singolo oggetto JWK. Va bene anche una chiave pubblica PEM (`-----BEGIN PUBLIC KEY-----`)."
  - q: "Perché un token con \"alg\": \"none\" non si verifica?"
    a: "Perché non c'è nulla da verificare: il token dichiara di non essere firmato. Accettare token del genere è una vulnerabilità classica; il server deve decidere quali algoritmi accettare invece di fidarsi dell'header. L'inspector mostra l'algoritmo in evidenza proprio perché salti all'occhio."
  - q: "La firma è valida ma l'API rifiuta comunque il token. Perché?"
    a: "Una firma valida è solo uno dei controlli. I server verificano anche `exp`, `nbf`, l'emittente (`iss`), il destinatario (`aud`) e spesso gli scope. Guarda i chip di stato e la tabella dei claim: un token scaduto o un audience sbagliato sono la causa più comune."
  - q: "Lo strumento salva il segreto o la chiave che incollo?"
    a: "No. Le chiavi vengono importate con `crypto.subtle.importKey` come non estraibili, usate una volta per la verifica e scartate con la pagina. Nulla viene scritto nella memoria del browser."
---

## Come funziona

### Decodifica

Un JWT è composto da tre segmenti Base64URL uniti da punti: `header.payload.signature`. L'inspector divide la stringa, controlla che i segmenti siano esattamente tre, converte il Base64URL in Base64 standard (sostituendo `-` con `+` e `_` con `/` e ripristinando il padding `=`), decodifica i byte come UTF-8 e legge header e payload con `JSON.parse`. Un input malformato produce un errore specifico invece di una schermata vuota.

I claim registrati del payload sono spiegati in una tabella. I claim temporali `exp` (scadenza), `nbf` (non prima di) e `iat` (emesso il) sono valori **NumericDate**, cioè secondi dal 1° gennaio 1970 UTC, quindi vengono convertiti nell'ora locale e in una descrizione relativa come "in 23 min" o "3 days ago". La barra di stato segnala un token scaduto, un token non ancora valido e un token senza `exp`.

### Verifica

La verifica usa la **Web Crypto API** integrata nel browser (`crypto.subtle`), non una libreria crittografica JavaScript:

- L'input firmato è la stringa ASCII `header.payload` esattamente come compare nel token. Non viene ricodificato, ed è per questo che un token modificato a mano non supera la verifica.
- **HS256/384/512**: il segreto viene importato come chiave HMAC grezza con SHA-256, SHA-384 o SHA-512, e `crypto.subtle.verify('HMAC', …)` controlla il MAC.
- **RS256/384/512**: la chiave pubblica viene importata come `RSASSA-PKCS1-v1_5` con l'hash corrispondente.
- **PS256/384/512**: importata come `RSA-PSS` e verificata con un salt lungo quanto l'hash (32, 48 o 64 byte), come richiede l'RFC 7518.
- **ES256/384/512**: importata come `ECDSA` su P-256, P-384 o P-521. Le firme ECDSA dei JWS sono la concatenazione grezza `r‖s`, il formato che si aspetta Web Crypto, quindi non serve alcuna conversione DER.

Le chiavi pubbliche possono essere in **PEM/SPKI** (il Base64 tra le righe `BEGIN/END PUBLIC KEY` viene decodificato in DER) o come oggetto **JWK** in JSON. Le chiavi importate non sono estraibili e vivono solo per la durata della verifica.

### Un tranello frequente

I segreti HMAC sono spesso configurati come stringhe Base64. Se il tuo backend decodifica il segreto prima di firmare, spunta *Secret is Base64URL-encoded*; altrimenti la stessa stringa visibile produce una chiave diversa e la firma non corrisponde.

## Casi d'uso

- **Debug dell'autenticazione.** Capisci perché una richiesta torna 401: `exp` scaduto, `aud` sbagliato, uno scope mancante o un token firmato da un'altra chiave.
- **Verificare l'integrazione con un identity provider.** Decodifica l'ID token di un login OAuth/OIDC e verificalo con la JWKS del provider prima di scrivere il codice del backend.
- **Security review e penetration test.** Individua token con `alg: none`, durate eccessive, dati sensibili nel payload o un `kid` che punta dove non dovrebbe.
- **Rotazione delle chiavi.** Conferma che i token emessi dopo una rotazione si verificano con la nuova chiave pubblica e quelli vecchi con la precedente.
- **Formazione.** Mostra come è fatto un token e perché il Base64URL è una codifica, non una cifratura.
