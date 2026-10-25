---
title: "Cron-Generator: Ausdrücke bauen & erklären"
description: "Cron-Ausdrücke visuell erstellen, jeden Cron in Klartext übersetzen und die nächsten 5 Ausführungen sehen. Kostenloser Crontab-Generator für Linux und CI."
intro: "**EasyCron** baut einen Cron-Ausdruck per Klick, übersetzt einen vorhandenen in Klartext und listet die nächsten fünf Ausführungszeiten. Es deckt die Standard-Crontab-Syntax mit fünf Feldern ab, die Linux-Cron, Kubernetes-CronJobs und die meisten CI-Scheduler verwenden."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["cron generator", "cron ausdruck", "crontab generator", "cron alle 5 minuten", "crontab beispiele", "cron ausdruck erklärt", "cronjob erstellen", "cron nächste ausführung"]
tags: ["linux", "devops", "cron", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/easy-cron/"
tool_title: "EasyCron Cron-Ausdruck-Generator"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Beginnen Sie mit einem **Preset** (alle 5 Minuten, werktags um 9 Uhr, monatlich am 1. …) oder mit dem Standard `* * * * *`."
  - "Legen Sie über die Reiter **Minute, Hour, Day, Month, Weekday** jedes Feld fest: alle Werte, ein Intervall wie alle 15 Minuten oder bestimmte Werte aus einem Raster. Schnellknöpfe decken übliche Fälle wie Bürozeiten oder Werktage ab."
  - "Ausdruck, Klartext-Beschreibung und **Next 5 runs** aktualisieren sich bei jedem Klick."
  - "Klicken Sie auf **Copy** und fügen Sie den Ausdruck in Ihre Crontab, Ihr CronJob-Manifest oder Ihre CI-Datei ein."
  - "Um einen vorhandenen Zeitplan zu verstehen, fügen Sie ihn in den **Reverse Translator** ein und klicken auf **Parse**: Sie erhalten Beschreibung und nächste Läufe, und der Builder lädt ihn zur Bearbeitung."
faq:
  - q: "Was bedeuten die fünf Felder eines Cron-Ausdrucks?"
    a: "Der Reihe nach: Minute (0–59), Stunde (0–23), Tag des Monats (1–31), Monat (1–12) und Wochentag (0–6, Sonntag = 0). `30 2 * * 1` bedeutet also jeden Montag um 02:30 Uhr. Ein Sternchen heißt „jeder Wert“ für dieses Feld."
  - q: "Wie lasse ich einen Cronjob alle 5 Minuten laufen?"
    a: "`*/5 * * * *`. `*/5` im Minutenfeld bedeutet jede fünfte Minute ab 0: 00, 05, 10 … 55. Entsprechend läuft `0 */2 * * *` zu jeder zweiten vollen Stunde und `*/15 9-17 * * 1-5` alle 15 Minuten während der Bürozeit an Werktagen."
  - q: "Was passiert, wenn Tag des Monats und Wochentag gesetzt sind?"
    a: "Standard-Cron (Vixie) führt den Job aus, wenn *eines von beiden* passt, nicht wenn beide passen. `0 9 1 * 1` läuft um 09:00 Uhr am 1. jedes Monats *und* jeden Montag. Die Berechnung der nächsten Läufe in EasyCron folgt derselben Regel, die viele überrascht."
  - q: "In welcher Zeitzone werden die nächsten Läufe angezeigt?"
    a: "In der Zeitzone Ihres Browsers. Ein Cron-Daemon nutzt die Zeitzone der Maschine, auf der er läuft, auf Servern und in Containern oft UTC. Kubernetes-CronJobs verwenden die Zeitzone des Controllers, sofern Sie kein `spec.timeZone` setzen. Läuft Ihr Server in UTC, rechnen Sie vorher um."
  - q: "Unterstützt EasyCron Sekunden, Namen wie MON oder JAN oder @daily?"
    a: "Nein. Es zielt auf die portable Syntax mit fünf Feldern: Zahlen, `*`, Bereiche wie `1-5`, Listen wie `1,15`, Schritte wie `*/10` und Bereiche mit Schritt wie `0-30/10`. Sekunden im Quartz-Stil sowie `L`, `W`, `#` und `?` werden nicht unterstützt. Schreiben Sie `0 0 * * *` statt `@daily` und `0` (nicht `7`) für Sonntag."
  - q: "Wird etwas an einen Server gesendet?"
    a: "Nein. Builder, Beschreibung und Berechnung der nächsten Läufe sind JavaScript in dieser Seite. Gespeichert wird nur Ihre Wahl zwischen hellem und dunklem Design, im localStorage des Browsers."
---

## So funktioniert es

### Den Ausdruck bauen

Jedes der fünf Felder hat einen eigenen Zustand: **every** (`*`), **interval** (`*/n`, mit sinnvollen Werten je Feld wie 5, 10, 15 oder 30 Minuten und 2, 3, 4, 6, 8 oder 12 Stunden) oder **bestimmte** Werte aus einem Raster. Im Modus „bestimmt“ werden die gewählten Zahlen sortiert und mit Kommas verbunden (`0,15,30,45`). Sind alle möglichen Werte ausgewählt, wird das Feld wieder zu `*`. Die fünf Teile werden mit Leerzeichen zum fertigen Ausdruck verbunden.

### Interpretieren und erklären

Der Reverse Translator trennt den Ausdruck an Leerzeichen und verlangt genau fünf Felder. Jedes Feld wird in die Menge der Werte aufgelöst, die es abdeckt:

| Syntax | Beispiel | Ergibt |
|---|---|---|
| `*` | `*` bei Stunden | 0, 1, 2 … 23 |
| `*/n` | `*/15` bei Minuten | 0, 15, 30, 45 |
| `a-b` | `1-5` bei Wochentagen | Mo … Fr |
| `a-b/n` | `0-30/10` bei Minuten | 0, 10, 20, 30 |
| Liste | `1,15` bei Tagen | 1. und 15. |

Die (englische) Beschreibung wird nach Regeln zusammengesetzt, die so klingen, wie ein Mensch es sagen würde: `*/5 * * * *` wird zu „Every 5 minutes“, `0 9 * * 1-5` zu „At 09:00, Monday through Friday“, `0 0 1 1 *` zu „At 00:00, on day 1 of the month, in January“.

### Die nächsten Läufe berechnen

Ab einer Minute in der Zukunft geht der Rechner die Zeit vorwärts durch und überspringt ganze Einheiten, die nicht passen können: Ein Monat außerhalb der Menge springt zum 1. des Folgemonats, ein unpassender Tag zu Mitternacht des nächsten Tages, eine unpassende Stunde zur nächsten Stunde. Passen Monat, Tag, Stunde und Minute, wird der Zeitpunkt notiert – bis fünf Läufe gefunden oder vier Jahre durchsucht sind. Deshalb melden unmögliche Zeitpläne wie `0 0 31 2 *` (31. Februar), dass es keinen künftigen Lauf gibt.

Die Tagesprüfung folgt der echten Cron-Semantik: Ist nur eines der beiden Tagesfelder eingeschränkt, entscheidet dieses; sind beide eingeschränkt, genügt es, wenn eines passt.

## Anwendungsfälle

- **Eine Crontab-Zeile schreiben** für Backups, Log-Rotation, Zertifikatserneuerung oder ein Aufräumskript, ohne die Feldreihenfolge erneut nachzuschlagen.
- **Kubernetes-CronJobs und CI-Pipelines.** `schedule:` in GitHub Actions, Pipeline-Zeitpläne in GitLab und `spec.schedule` in Kubernetes verwenden dieselben fünf Felder.
- **Fremde Zeitpläne verstehen.** Fügen Sie das kryptische `15 3 */2 * *` aus einer Konfiguration ein und lesen Sie „At 03:15, every 2nd day of the month“.
- **Fehler vor der Produktion finden**, etwa einen Job für „werktags um 9“, der auch am 1. des Monats läuft, weil beide Tagesfelder gesetzt wurden.
- **Wartungsfenster planen.** Prüfen Sie genau, wann die nächsten fünf Läufe stattfinden, und rechnen Sie in die Zeitzone des Servers um.
