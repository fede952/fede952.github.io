---
title: "Base64 kodieren & dekodieren online (UTF-8)"
description: "Text in Base64 kodieren oder Base64 und Base64URL in Text dekodieren, mit vollem UTF-8-Support für Umlaute und Emoji. Kostenlos, sofort, im Browser."
intro: "Wandeln Sie Text in **Base64** um und zurück. Die Kodierung ist UTF-8-sicher, und die Dekodierung akzeptiert auch die URL-sichere Variante **Base64URL** aus JWTs und Web-APIs, mit oder ohne `=`-Padding. Nichts, was Sie einfügen, verlässt diese Seite."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["base64 kodieren", "base64 dekodieren", "base64 decoder", "base64 online", "base64url dekodieren", "base64 in text", "base64 utf-8", "base64 konverter"]
tags: ["kodierung", "entwickler-tools", "base64", "tool"]
app_category: "DeveloperApplication"
tool_partial: "base64-converter"
howto:
  - "Geben Sie in **Eingabetext** ein, was Sie umwandeln möchten: Klartext zum Kodieren oder einen Base64-String zum Dekodieren."
  - "Klicken Sie auf **In Base64 kodieren**, um den Text in Base64 umzuwandeln. Umlaute, nichtlateinische Schriften und Emoji werden als UTF-8 kodiert."
  - "Klicken Sie auf **Aus Base64 dekodieren**, um Base64 zurück in Text zu wandeln. Standard-Base64, Base64URL (`-` und `_`), fehlendes Padding und Zeilenumbrüche werden akzeptiert."
  - "Lesen Sie das Ergebnis unter **Ergebnis** ab und legen Sie es mit **Kopieren** in die Zwischenablage."
  - "Sind die dekodierten Bytes kein gültiges UTF-8, meldet das Tool das: Wahrscheinlich handelt es sich um Binärdaten (ein Bild, komprimierte Daten oder einen Schlüssel) und nicht um Text."
faq:
  - q: "Wofür wird Base64 verwendet?"
    a: "Base64 stellt Binärdaten mit 64 druckbaren ASCII-Zeichen dar, damit sie durch Systeme laufen können, die nur Text verarbeiten: E-Mail-Anhänge (MIME), Data-URLs in HTML und CSS, JSON-Payloads, HTTP-Basic-Auth-Header, Kubernetes-Secrets und die drei Teile eines JSON Web Tokens."
  - q: "Ist Base64 eine Verschlüsselung?"
    a: "Nein. Es ist eine Kodierung ohne Schlüssel: Jeder kann sie sofort dekodieren, wie diese Seite zeigt. Verwenden Sie Base64 nie, um Passwörter oder Geheimnisse zu verstecken; Kubernetes-Secrets etwa sind nur Base64-kodiert, nicht verschlüsselt, sofern Sie keine Encryption at Rest aktivieren."
  - q: "Was ist der Unterschied zwischen Base64 und Base64URL?"
    a: "Base64URL (RFC 4648, Abschnitt 5) ersetzt `+` durch `-` und `/` durch `_`, damit das Ergebnis in URLs und Dateinamen sicher ist, und lässt meist das `=`-Padding weg. JWTs und viele APIs nutzen es. Dieses Tool dekodiert beides; beim Kodieren erzeugt es Standard-Base64."
  - q: "Warum sieht mein dekodierter Text verstümmelt aus?"
    a: "Entweder war die Eingabe von vornherein kein Text (zum Beispiel ein Bild oder ein gzip-Stream), oder der Originaltext wurde mit einem anderen Zeichensatz kodiert, etwa Latin-1 statt UTF-8. Das Tool dekodiert als UTF-8 und warnt, wenn die Bytes kein gültiges UTF-8 sind."
  - q: "Warum ist Base64 etwa ein Drittel größer als das Original?"
    a: "Aus je 3 Byte Eingabe werden 4 Base64-Zeichen, weil jedes Zeichen 6 Bit trägt (2⁶ = 64). Das sind 33 % Mehraufwand, plus bis zu zwei `=`-Padding-Zeichen am Ende. Aus einem 30-KB-Bild wird eine 40-KB-Data-URL."
  - q: "Wird der eingefügte Text irgendwohin gesendet?"
    a: "Nein. Kodierung und Dekodierung nutzen die eingebauten Browserfunktionen `btoa`, `atob`, `TextEncoder` und `TextDecoder` innerhalb dieser Seite. Es wird nichts hochgeladen oder gespeichert."
---

## So funktioniert es

### Kodierung

JavaScripts eingebaute Funktion `btoa()` versteht nur Zeichen aus dem Latin-1-Bereich; ein direkter Aufruf mit `"Straße €"` wirft einen Fehler. Das Tool umgeht das durch korrekte Kodierung:

1. `TextEncoder` wandelt den Text in **UTF-8-Bytes** um: `ß` wird zu `C3 9F`, `€` zu `E2 82 AC`.
2. Jedes Byte wird einem Ein-Byte-Zeichen zugeordnet, und `btoa()` macht aus diesem Byte-String Base64.

Base64 arbeitet in Gruppen von **3 Byte = 24 Bit**, aufgeteilt in vier 6-Bit-Werte, die je einem Zeichen des Alphabets `A–Z a–z 0–9 + /` entsprechen. Ist die Eingabelänge kein Vielfaches von 3, wird die letzte Gruppe mit `=` aufgefüllt:

| Text | UTF-8-Bytes | Base64 |
|---|---|---|
| `Man` | `4D 61 6E` | `TWFu` |
| `Ma` | `4D 61` | `TWE=` |
| `M` | `4D` | `TQ==` |
| `é` | `C3 A9` | `w6k=` |

### Dekodierung

Die Dekodierung kehrt den Vorgang um, mit etwas Toleranz für echte Eingaben:

- Alle Leerzeichen und Zeilenumbrüche werden entfernt (MIME bricht Base64 nach 76 Zeichen um).
- Die **Base64URL**-Zeichen `-` und `_` werden auf `+` und `/` zurückgeführt und fehlendes `=`-Padding wird ergänzt, sodass Sie ein JWT-Segment unverändert einfügen können.
- `atob()` macht aus Base64 Bytes, und `TextDecoder` mit `fatal: true` interpretiert sie als UTF-8. Sind die Bytes kein gültiges UTF-8, zeigt das Tool trotzdem eine bestmögliche Dekodierung, warnt aber, dass es sich wohl um Binärdaten handelt.
- Ein String, dessen Länge bei Division durch 4 den Rest 1 lässt, kann nie gültiges Base64 sein und wird mit einer klaren Meldung abgelehnt.

## Anwendungsfälle

- **Ein JWT von Hand lesen.** Fügen Sie das mittlere Segment eines Tokens ein, um seine JSON-Claims zu sehen (für die Signaturprüfung gibt es den JWT Inspector).
- **Kubernetes und Docker.** Dekodieren Sie die Werte eines Secret-Manifests oder kodieren Sie einen Wert, bevor er unter `data:` landet.
- **HTTP Basic Auth.** Dekodieren Sie einen Header `Authorization: Basic …`, um das enthaltene `benutzer:passwort` zu sehen, oder bauen Sie einen für eine Testanfrage.
- **Data-URLs und E-Mail.** Untersuchen Sie `data:`-URIs und MIME-Teile im Rohquelltext einer E-Mail.
- **APIs debuggen.** Viele APIs kodieren binäre Felder oder verschachteltes JSON in Base64 – dekodieren Sie sie, um zu sehen, was wirklich gesendet wurde.
