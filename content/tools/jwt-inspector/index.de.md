---
title: "JWT Decoder & Signaturprüfung online"
description: "Dekodieren Sie JSON Web Tokens, lesen Sie Claims und Ablaufzeit und prüfen Sie HS256-, RS256-, PS256- oder ES256-Signaturen per Web Crypto API im Browser."
intro: "Fügen Sie ein **JSON Web Token** ein, um Header und Payload zu sehen, `exp`, `nbf` und `iat` als lesbare Zeit zu prüfen und die Signatur mit einem Secret oder Public Key zu verifizieren. Dekodierung und Prüfung laufen in Ihrem Browser; das Token wird nie übertragen."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["jwt decoder", "jwt dekodieren", "jwt signatur prüfen", "jwt online", "jwt token prüfen", "jwt rs256 verifizieren", "jwt ablaufzeit", "jwt debugger"]
tags: ["sicherheit", "entwickler-tools", "jwt", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/jwt-inspector/"
tool_title: "TokenLens: JWT-Decoder und Signaturprüfung"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-read; clipboard-write"
howto:
  - "Fügen Sie ein Token in das Feld ein oder klicken Sie auf **Paste**, um es aus der Zwischenablage zu lesen. **Load sample** lädt ein HS256-Beispieltoken."
  - "Das Token wird in seine drei farbigen Teile zerlegt und sofort dekodiert: Header und Payload erscheinen als hervorgehobenes JSON."
  - "Prüfen Sie die Status-Chips: Algorithmus, `typ`, `kid` und ob das Token abgelaufen oder noch nicht gültig ist. Die Claims-Tabelle übersetzt `exp`, `nbf` und `iat` in lokale Datumsangaben."
  - "Zum Verifizieren fügen Sie für HS256/384/512 das **HMAC-Secret** ein (Häkchen bei *Secret is Base64URL-encoded*, falls zutreffend) oder für RS, PS und ES den **Public Key** des Ausstellers als PEM oder JWK."
  - "Klicken Sie auf **Verify signature**. Grün: Die Signatur passt zum Schlüssel, das Token ist unverändert. Rot: falscher Schlüssel oder manipuliertes Token."
faq:
  - q: "Ist es sicher, hier ein Produktions-JWT einzufügen?"
    a: "Das Tool läuft komplett im Browser und stellt mit dem Token keine Netzwerkanfragen, bei uns wird also nichts protokolliert. Trotzdem ist ein gültiges Access Token ein Passwort mit Ablaufdatum: Wer es sieht, kann es bis zum Ablauf benutzen. Nutzen Sie lieber abgelaufene oder Test-Tokens – und nie ein Tool, das Sie nicht prüfen können."
  - q: "Was ist der Unterschied zwischen Dekodieren und Verifizieren?"
    a: "Dekodieren kehrt nur die Base64URL-Kodierung von Header und Payload um – das kann jeder, denn ein JWT ist signiert, nicht verschlüsselt. Verifizieren berechnet die Signatur über `header.payload` mit dem Schlüssel neu und vergleicht sie mit dem dritten Segment. Nur die Verifizierung belegt, dass das Token vom Schlüsselinhaber stammt und unverändert ist."
  - q: "Welche Algorithmen werden unterstützt?"
    a: "HS256, HS384 und HS512 (HMAC mit gemeinsamem Secret); RS256, RS384 und RS512 (RSA PKCS#1 v1.5); PS256, PS384 und PS512 (RSA-PSS); ES256, ES384 und ES512 (ECDSA auf P-256, P-384 und P-521). Tokens mit `alg: none` oder anderen Algorithmen werden dekodiert, aber nicht verifiziert."
  - q: "Wo finde ich den Public Key für ein RS256-Token?"
    a: "Die meisten Identity Provider veröffentlichen ihre Schlüssel als JWKS unter einer URL wie `https://issuer/.well-known/jwks.json`. Suchen Sie den Eintrag, dessen `kid` zum Token-Header passt, und fügen Sie dieses einzelne JWK-Objekt ein. Ein PEM-Public-Key (`-----BEGIN PUBLIC KEY-----`) funktioniert ebenfalls."
  - q: "Warum lässt sich ein Token mit \"alg\": \"none\" nicht verifizieren?"
    a: "Weil es nichts zu prüfen gibt: Das Token behauptet, unsigniert zu sein. Solche Tokens zu akzeptieren ist eine klassische Schwachstelle; der Server muss selbst festlegen, welche Algorithmen er akzeptiert, statt dem Header zu vertrauen. Der Inspector zeigt den Algorithmus deshalb gut sichtbar an."
  - q: "Die Signatur ist gültig, aber die API lehnt das Token ab. Warum?"
    a: "Eine gültige Signatur ist nur eine Prüfung von mehreren. Server validieren auch `exp`, `nbf`, den Aussteller (`iss`), die Zielgruppe (`aud`) und oft Scopes. Sehen Sie sich Status-Chips und Claims-Tabelle an: Ein abgelaufenes Token oder eine falsche Audience ist die häufigste Ursache."
  - q: "Speichert das Tool das Secret oder den Schlüssel?"
    a: "Nein. Schlüssel werden mit `crypto.subtle.importKey` als nicht exportierbar importiert, einmal für die Prüfung verwendet und mit der Seite verworfen. Es wird nichts in den Browserspeicher geschrieben."
---

## So funktioniert es

### Dekodierung

Ein JWT besteht aus drei Base64URL-Segmenten, verbunden durch Punkte: `header.payload.signature`. Der Inspector teilt den String, prüft, dass es genau drei Segmente sind, wandelt Base64URL in Standard-Base64 um (`-` wird zu `+`, `_` zu `/`, das `=`-Padding wird ergänzt), dekodiert die Bytes als UTF-8 und liest Header und Payload mit `JSON.parse`. Fehlerhafte Eingaben erzeugen eine konkrete Fehlermeldung statt eines leeren Bildschirms.

Die registrierten Claims des Payloads werden in einer Tabelle erklärt. Die Zeit-Claims `exp` (Ablauf), `nbf` (nicht vor) und `iat` (ausgestellt am) sind **NumericDate**-Werte, also Sekunden seit dem 1. Januar 1970 UTC; sie werden in Ihre Ortszeit und eine relative Angabe wie „in 23 min“ oder „3 days ago“ umgerechnet. Die Statusleiste markiert abgelaufene Tokens, noch nicht gültige Tokens und Tokens ganz ohne `exp`.

### Verifizierung

Die Prüfung nutzt die eingebaute **Web Crypto API** des Browsers (`crypto.subtle`), keine JavaScript-Kryptobibliothek:

- Die signierte Eingabe ist der ASCII-String `header.payload`, genau wie er im Token steht. Er wird nicht neu kodiert – deshalb scheitert ein von Hand bearbeitetes Token.
- **HS256/384/512**: Das Secret wird als roher HMAC-Schlüssel mit SHA-256, SHA-384 oder SHA-512 importiert, `crypto.subtle.verify('HMAC', …)` prüft den MAC.
- **RS256/384/512**: Der Public Key wird als `RSASSA-PKCS1-v1_5` mit dem passenden Hash importiert.
- **PS256/384/512**: Import als `RSA-PSS`, geprüft mit einer Salt-Länge gleich der Hash-Länge (32, 48 oder 64 Byte), wie RFC 7518 es verlangt.
- **ES256/384/512**: Import als `ECDSA` auf P-256, P-384 oder P-521. JWS-ECDSA-Signaturen sind die rohe Verkettung `r‖s`, genau das Format, das Web Crypto erwartet – eine DER-Umwandlung entfällt.

Public Keys können als **PEM/SPKI** (das Base64 zwischen den Zeilen `BEGIN/END PUBLIC KEY` wird zu DER dekodiert) oder als **JWK**-JSON-Objekt angegeben werden. Importierte Schlüssel sind nicht exportierbar und existieren nur während der Prüfung.

### Eine häufige Falle

HMAC-Secrets werden oft als Base64-Strings konfiguriert. Dekodiert Ihr Backend das Secret vor dem Signieren, setzen Sie das Häkchen bei *Secret is Base64URL-encoded*; sonst ergibt derselbe sichtbare String einen anderen Schlüssel, und die Signatur passt nicht.

## Anwendungsfälle

- **Authentifizierung debuggen.** Finden Sie heraus, warum eine Anfrage 401 liefert: abgelaufenes `exp`, falsches `aud`, fehlender Scope oder ein mit einem anderen Schlüssel signiertes Token.
- **Identity-Provider-Integration prüfen.** Dekodieren Sie das ID-Token eines OAuth/OIDC-Logins und verifizieren Sie es gegen die JWKS des Anbieters, bevor Sie Backend-Code schreiben.
- **Security Reviews und Pentests.** Erkennen Sie Tokens mit `alg: none`, zu langen Laufzeiten, sensiblen Daten im Payload oder einer `kid`, die an unerwartete Stellen zeigt.
- **Schlüsselrotation.** Bestätigen Sie, dass nach einer Rotation ausgestellte Tokens mit dem neuen Public Key und ältere mit dem vorherigen verifizieren.
- **Lehre.** Zeigen Sie, wie ein Token aufgebaut ist und warum Base64URL eine Kodierung und keine Verschlüsselung ist.
