---
title: "Unix-Zeitstempel umrechnen (Epoch → Datum)"
description: "Unix-Zeitstempel in Datumsangaben und Datum in Epoch-Zeit umrechnen, in UTC und Ortszeit. Sekunden oder Millisekunden werden erkannt. Mit Live-Epoch-Uhr."
intro: "**ChronoSync** rechnet **Unix-Zeitstempel (Epoch)** in lesbare Datumsangaben um und zurück. Es zeigt den aktuellen Zeitstempel live, akzeptiert Sekunden oder Millisekunden und liefert jedes Ergebnis in UTC und in Ihrer Zeitzone."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["unix zeitstempel umrechnen", "epoch converter", "timestamp in datum", "datum in timestamp", "aktueller unix timestamp", "unix zeit", "millisekunden in datum", "epoch umrechnen"]
tags: ["entwickler-tools", "zeit", "konverter", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/chrono-sync/"
tool_title: "ChronoSync Unix-Zeitstempel-Konverter"
tool_height: 700
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Lesen Sie oben den **Aktuellen UNIX-Zeitstempel** ab: Er aktualisiert sich jede Sekunde, darunter derselbe Zeitpunkt in UTC."
  - "Um einen Zeitstempel in ein Datum umzuwandeln, fügen Sie ihn in **Zeitstempel → Datum** ein und klicken auf **Konvertieren**. 10-stellige Werte gelten als Sekunden, 13-stellige als Millisekunden."
  - "Lesen Sie das Ergebnis: zuerst das Datum in UTC, dann derselbe Zeitpunkt in der lokalen Zeitzone Ihres Browsers."
  - "Für einen Zeitstempel wählen Sie Datum und Uhrzeit unter **Datum → Zeitstempel** (Ortszeit, sekundengenau) und klicken auf **Konvertieren**."
  - "Mit dem kleinen Kopierknopf neben jedem Ergebnis legen Sie es in die Zwischenablage."
faq:
  - q: "Was ist ein Unix-Zeitstempel?"
    a: "Die Anzahl der Sekunden seit dem 1. Januar 1970, 00:00:00 UTC, der „Unix-Epoch“, ohne Schaltsekunden. Zu einem bestimmten Zeitpunkt ist er überall auf der Welt gleich – deshalb nutzen ihn Server, Datenbanken und Logs: 1700000000 ist der 14. November 2023, 22:13:20 UTC, egal in welcher Zeitzone Sie sind."
  - q: "Sekunden oder Millisekunden?"
    a: "Unix-Tools, PHP, Pythons `time.time()` (als Ganzzahl) und die meisten Datenbanken verwenden Sekunden, derzeit 10 Stellen. JavaScripts `Date.now()`, Javas `System.currentTimeMillis()` und viele APIs verwenden Millisekunden, 13 Stellen. ChronoSync behandelt Eingaben ab 13 Stellen als Millisekunden und kennzeichnet das Ergebnis mit (ms)."
  - q: "Warum liegt mein umgerechnetes Datum ein, zwei Stunden daneben?"
    a: "Weil ein Zeitstempel keine Zeitzone hat, nur seine Anzeige. Vergleichen Sie die UTC-Zeile, nicht die lokale, mit Server oder Logs, die meist in UTC laufen. Die Sommerzeit erklärt Abweichungen, die nur in einem Teil des Jahres auftreten."
  - q: "Was ist das Jahr-2038-Problem?"
    a: "Systeme, die Zeitstempel als vorzeichenbehaftete 32-Bit-Ganzzahl speichern, laufen bei 2147483647 über – am 19. Januar 2038 um 03:14:07 UTC. Danach wird der Wert negativ, und Datumsangaben springen ins Jahr 1901. Moderne Systeme nutzen 64 Bit, eingebettete Geräte und alte Dateiformate sind aber weiter betroffen."
  - q: "Funktioniert es mit Daten vor 1970?"
    a: "Ja. Negative Zeitstempel zählen die Sekunden vor dem Epoch: -86400 ist der 31. Dezember 1969, 00:00 UTC. Minuszeichen eingeben und wie gewohnt umrechnen."
  - q: "Wie bekomme ich den aktuellen Zeitstempel im Code?"
    a: "Bash: `date +%s`. Python: `int(time.time())`. JavaScript: `Math.floor(Date.now() / 1000)`. PHP: `time()`. SQL (PostgreSQL): `extract(epoch from now())`. PowerShell: `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`."
---

## So funktioniert es

Alles ist reines JavaScript mit dem eingebauten `Date`-Objekt des Browsers, das die Zeit intern als Millisekunden seit dem Epoch speichert.

**Live-Uhr.** Jede Sekunde berechnet die Seite `Math.floor(Date.now() / 1000)` und zeigt den Wert neben `toISOString()` desselben Zeitpunkts im Format `JJJJ-MM-TT HH:MM:SS UTC`.

**Zeitstempel → Datum.** Die Eingabe muss eine Ganzzahl sein, gern auch negativ. Hat sie 13 oder mehr Stellen, gilt sie als Millisekunden, sonst wird sie mit 1000 multipliziert. Das resultierende `Date` wird zweimal ausgegeben:

1. in **UTC**, über `toISOString()` – die eindeutige Form zum Abgleich mit Logs und Servern;
2. in **Ortszeit**, über `toLocaleString()`, mit Zeitzone und Datumsformat Ihres Browsers.

**Datum → Zeitstempel.** Die Auswahl ist ein `<input type="datetime-local">`, das keine eigene Zeitzone hat; der Browser interpretiert es in Ihrer lokalen Zone. `getTime() / 1000`, abgerundet, ergibt die Epoch-Sekunden. Voreingestellt ist die aktuelle Ortszeit.

| Zeitstempel | UTC-Datum | Hinweis |
|---|---|---|
| `0` | 1970-01-01 00:00:00 | Der Epoch |
| `1000000000` | 2001-09-09 01:46:40 | Erster 10-stelliger Zeitstempel |
| `1700000000` | 2023-11-14 22:13:20 | |
| `2000000000` | 2033-05-18 03:33:20 | |
| `2147483647` | 2038-01-19 03:14:07 | Größter vorzeichenbehafteter 32-Bit-Wert |
| `-86400` | 1969-12-31 00:00:00 | Ein Tag vor dem Epoch |

Schaltsekunden gehören nicht zur Unix-Zeit; ein Zeitstempel entspricht also genau einem UTC-Zeitpunkt (bis auf die seltene Schaltsekunde selbst), und zwei Zeitstempel unterscheiden sich exakt um ihre Sekundenzahl.

## Anwendungsfälle

- **Logs und JWTs lesen.** Machen Sie aus `exp`, `iat` und Log-Feldern wie `1729771200` ein Datum, mit dem Sie arbeiten können.
- **Zeitzonen debuggen.** Sehen Sie sofort, ob ein gespeicherter Wert Mitternacht UTC oder Mitternacht Ortszeit ist.
- **Abfragen schreiben.** Holen Sie den Zeitstempel für „1. März 2026 00:00“ für eine SQL-`WHERE`-Klausel oder einen API-Filter.
- **Zwischen Sprachen umrechnen.** Prüfen Sie, ob ein Wert aus JavaScript (ms) und einer aus Python (s) denselben Moment beschreiben.
- **Cron und Planung.** Kontrollieren Sie, wann ein in Epoch-Zeit geplanter Job tatsächlich läuft.
