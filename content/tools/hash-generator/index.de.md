---
title: "Hash-Generator: MD5, SHA-256, SHA-512"
description: "Erzeugen Sie MD5-, SHA-1-, SHA-256- und SHA-512-Hashes beliebiger Texte beim Tippen, mit UTF-8 und Kopieren per Klick. Berechnet im Browser, ohne Upload."
intro: "Text eingeben oder einfügen und sofort die **MD5-, SHA-1-, SHA-256- und SHA-512-Hashes** erhalten, aktualisiert bei jedem Tastendruck. Die SHA-Familie berechnet die Web Crypto API Ihres Browsers; nichts von Ihrer Eingabe wird übertragen."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["hash generator", "sha256 generator", "md5 generator", "sha512 hash online", "sha1 hash", "text in sha256", "prüfsumme berechnen", "hash rechner online"]
tags: ["kryptografie", "hash", "entwickler-tools", "tool"]
app_category: "DeveloperApplication"
tool_partial: "hash-generator"
howto:
  - "Geben Sie Ihren Text in **Eingabetext** ein oder fügen Sie ihn ein. Alle vier Hashes werden bei jedem Tastendruck neu berechnet."
  - "Lesen Sie das benötigte Ergebnis ab: **MD5** (32 Hex-Zeichen), **SHA-1** (40), **SHA-256** (64) oder **SHA-512** (128)."
  - "Mit **Kopieren** neben einem Hash legen Sie ihn in die Zwischenablage."
  - "Zum Vergleich mit einem vorgegebenen Hash fügen Sie beide in einen Editor ein oder vergleichen Zeichen für Zeichen: Ein einziges abweichendes Zeichen bedeutet eine andere Eingabe."
  - "Mit **Alles leeren** löschen Sie Eingabe und Ergebnisse."
faq:
  - q: "Welchen Hash-Algorithmus sollte ich verwenden?"
    a: "Für Integritätsprüfungen, Fingerprints und neue Systeme SHA-256 (oder SHA-512). MD5 und SHA-1 sind sicherheitstechnisch gebrochen: Es gibt praktische Kollisionsangriffe, sie dürfen also nicht für Signaturen oder Zertifikate verwendet werden. Für Zwecke ohne Sicherheitsanspruch, etwa Cache-Schlüssel oder den Abgleich alter Prüfsummen, taugen sie weiterhin."
  - q: "Kann ich mit diesem Tool ein Passwort hashen?"
    a: "Sie können den SHA-256 jeder Zeichenkette berechnen, aber ein einfacher SHA-Hash ist der falsche Weg, Passwörter zu speichern: Er ist auf Geschwindigkeit ausgelegt, Angreifer können Milliarden Versuche pro Sekunde testen. Echte Systeme verwenden eine langsame, gesalzene Passwort-Hash-Funktion wie Argon2id, bcrypt, scrypt oder PBKDF2."
  - q: "Warum unterscheidet sich mein Hash von dem eines anderen Tools?"
    a: "Fast immer ist die Eingabe anders. Achten Sie auf einen abschließenden Zeilenumbruch (`echo` fügt einen an; nutzen Sie `echo -n`), Leerzeichen, Windows-Zeilenenden `\\r\\n` oder eine andere Textkodierung. Dieses Tool hasht exakt die Zeichen im Feld, kodiert als UTF-8."
  - q: "Kann ich eine Datei hashen?"
    a: "Nicht mit dieser Seite, sie verarbeitet Text. Für Dateien nutzen Sie die Kommandozeile: `sha256sum datei` unter Linux, `shasum -a 256 datei` unter macOS oder `Get-FileHash datei -Algorithm SHA256` in der Windows PowerShell."
  - q: "Lässt sich ein Hash umkehren oder entschlüsseln?"
    a: "Nein. Ein Hash ist eine Einwegfunktion: Es gibt keinen Schlüssel und keinen Weg, aus der Ausgabe die Eingabe zu berechnen. Websites, die „MD5 entschlüsseln“, schlagen nur vorberechnete Hashes gängiger Wörter nach – genau deshalb schützt Hashing kurze oder häufige Eingaben nicht."
  - q: "Wird meine Eingabe an einen Server geschickt?"
    a: "Nein. SHA-1, SHA-256 und SHA-512 werden mit `crypto.subtle.digest()` berechnet, MD5 mit einer JavaScript-Implementierung, alles innerhalb dieser Seite. Es gibt keine Netzwerkanfragen mit Ihrer Eingabe."
---

## So funktioniert es

Bei jeder Eingabe liest das Tool das Textfeld, wandelt es mit `TextEncoder` in Bytes um (UTF-8, also wird `ä` zu zwei Bytes und ein Emoji zu vier) und führt mit `Promise.all` vier Hash-Funktionen parallel aus:

- **SHA-1, SHA-256 und SHA-512** laufen über die native **Web Crypto API** des Browsers: `crypto.subtle.digest('SHA-256', bytes)` liefert einen `ArrayBuffer`, der in kleingeschriebenes Hexadezimal umgewandelt wird.
- **MD5** gehört nicht zu Web Crypto, weil es als gebrochen gilt; es wird deshalb von einer kompakten JavaScript-Implementierung von RFC 1321 auf denselben UTF-8-Bytes berechnet.

Die Ergebnisse sind Hex-Strings, deren Länge der Algorithmus festlegt, egal wie groß die Eingabe ist:

| Algorithmus | Ausgabegröße | Hex-Zeichen | Status |
|---|---|---|---|
| MD5 | 128 Bit | 32 | Gebrochen (Kollisionen seit 2004) |
| SHA-1 | 160 Bit | 40 | Gebrochen (praktische Kollision, 2017) |
| SHA-256 | 256 Bit | 64 | Sicher, der übliche Standard |
| SHA-512 | 512 Bit | 128 | Sicher, schneller auf 64-Bit-CPUs |

Zwei Eigenschaften machen diese Funktionen nützlich. Sie sind **deterministisch**: Dieselbe Eingabe ergibt auf jedem Rechner denselben Hash. Und sie haben einen **Lawineneffekt**: Ändert sich ein Zeichen, kippt etwa die Hälfte der Ausgabebits, sodass `Hallo` und `hallo` völlig unterschiedliche SHA-256-Werte haben. Die Schaltflächen `Kopieren` nutzen die Clipboard API mit einem Fallback für ältere Browser.

### Text, keine Dateien

Die Eingabe ist der Text im Feld; die Hashes stimmen mit Kommandozeilen-Tools also nur überein, wenn die Bytes exakt gleich sind. `printf 'Hallo, Welt!' | sha256sum` und dieses Tool stimmen überein, `echo 'Hallo, Welt!' | sha256sum` nicht, weil `echo` einen Zeilenumbruch anhängt.

## Anwendungsfälle

- **Prüfsummen kontrollieren.** Viele Projekte veröffentlichen den SHA-256 eines Release-Strings oder einer kleinen Konfiguration – Text einfügen und vergleichen.
- **Signaturen und APIs debuggen.** Prüfen Sie den Hash, den eine API für einen Payload erwartet, oder den SHA-256, der in eine AWS Signature V4 oder eine Webhook-Prüfung eingeht.
- **Cache-Schlüssel und Deduplizierung.** Leiten Sie aus dem Text einer URL, einer Abfrage oder eines Dokuments eine stabile Kennung ab.
- **Kryptografie lernen.** Beobachten Sie den Lawineneffekt live, vergleichen Sie Digest-Längen und sehen Sie, warum MD5 und SHA-1 für Sicherheit ausgedient haben.
- **Altdaten abgleichen.** Erzeugen Sie einen MD5- oder SHA-1-Wert nach, den ein altes System gespeichert hat, um ihn auf etwas Stärkeres zu migrieren.
