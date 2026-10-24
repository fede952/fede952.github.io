---
title: "Wörter zählen & Groß-/Kleinschreibung"
description: "Wörter, Zeichen, Zeilen und Lesezeit live zählen, dann Groß-/Kleinschreibung ändern, doppelte Zeilen entfernen, Leerraum bereinigen oder Leetspeak nutzen."
intro: "**StringMaster** ist eine kleine Text-Werkbank. Fügen Sie beliebigen Text ein: Wörter, Zeichen, Zeilen und Lesezeit werden beim Tippen gezählt, und per Klick ändern Sie die Schreibweise, entfernen doppelte Zeilen, bereinigen Leerraum oder verwandeln den Text in Leetspeak. Der Text bleibt in Ihrem Browser-Tab."
date: 2026-02-10
lastmod: 2026-10-24
reviewed: false
keywords: ["wörter zählen", "zeichen zählen", "text tools online", "groß kleinschreibung umwandeln", "doppelte zeilen entfernen", "leerzeichen entfernen online", "leetspeak konverter", "lesezeit berechnen"]
tags: ["text", "entwickler-tools", "schreiben", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/string-master/"
tool_title: "StringMaster Text-Werkzeuge"
tool_height: 750
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Fügen Sie Ihren Text in das Feld **Eingabe** ein oder tippen Sie ihn. **Wörter**, **Zeichen**, **Zeilen** und **Lesezeit** aktualisieren sich bei jedem Tastendruck."
  - "Klicken Sie auf **Großbuchstaben** oder **Kleinbuchstaben**, um den gesamten Text umzuwandeln."
  - "**Duplikate entfernen** behält nur das erste Vorkommen jeder Zeile; **Leerzeichen entf.** entfernt Leerraum an Zeilenanfang und -ende und fasst Leerzeilen zusammen."
  - "Mit **Hacker-Modus** wird der Text in Leetspeak umgeschrieben (`hello` → `h3110`)."
  - "**Kopieren** legt das Ergebnis in die Zwischenablage. Umwandlungen ersetzen den Text direkt – kopieren Sie das Original vorher, falls Sie es noch brauchen."
faq:
  - q: "Wie werden Wörter gezählt?"
    a: "Der Text wird an jeder Folge von Leerraum (Leerzeichen, Tabs, Zeilenumbrüche) getrennt: `Ad-hoc-Lösung` ist ein Wort, `z. B. dies` sind drei. Sprachen ohne Leerzeichen wie Chinesisch oder Japanisch ergeben ein Wort pro Block – nutzen Sie dort die Zeichenzahl."
  - q: "Zählen Emojis und Umlaute als ein Zeichen?"
    a: "Ja. Der Zähler nutzt die Graphem-Segmentierung des Browsers (`Intl.Segmenter`), daher zählen 👍, ä und sogar ein aus mehreren Codepoints zusammengesetztes Familien-Emoji jeweils einmal – so, wie Sie sie sehen. Manche Plattformen, etwa SMS, zählen anders (in UTF-16-Einheiten oder Bytes) und erreichen ihr Limit früher."
  - q: "Wie wird die Lesezeit geschätzt?"
    a: "Wortzahl geteilt durch 200 Wörter pro Minute, ein üblicher Durchschnitt beim Lesen am Bildschirm, aufgerundet. Unter einer Minute werden Sekunden angezeigt (`45s`), darüber ganze Minuten (`4m`). Fachliche oder dichte Texte liest man meist langsamer."
  - q: "Unterscheidet Duplikate entfernen Groß- und Kleinschreibung?"
    a: "Ja, und es vergleicht exakt: `Apfel`, `apfel` und `apfel ` (mit Leerzeichen am Ende) sind drei verschiedene Zeilen. Wenden Sie vorher **Leerzeichen entf.** und **Kleinbuchstaben** an, wenn Sie lockerer vergleichen möchten. Die Reihenfolge der ersten Vorkommen bleibt erhalten, wiederholte Leerzeilen werden ebenfalls zu einer."
  - q: "Kann ich eine Umwandlung rückgängig machen?"
    a: "Es gibt keinen Rückgängig-Knopf, und da der Text per Skript ersetzt wird, holt Strg+Z ihn nicht in jedem Browser zurück. Kleinbuchstaben, Duplikate entfernen, Leerzeichen entf. und Hacker-Modus verlieren Information – behalten Sie eine Kopie des Originals."
  - q: "Lässt sich Leetspeak zurückwandeln?"
    a: "Nicht zuverlässig. Sowohl `i` als auch `l` werden zu `1`, und Ziffern, die schon im Text standen, sind von ersetzten Buchstaben nicht zu unterscheiden. Der Hacker-Modus ist ein Stil-Effekt in eine Richtung, keine Kodierung."
  - q: "Wird mein Text irgendwohin gesendet?"
    a: "Nein. Zählung und Umwandlungen sind einfaches JavaScript in der Seite; nichts wird gespeichert oder übertragen. Sie können es also bedenkenlos für Entwürfe, Logs oder interne Dokumente nutzen."
---

## So funktioniert es

Jeder Tastendruck im Eingabefeld startet dieselbe kleine Analyse:

- **Wörter** = Anzahl nicht leerer Blöcke, nachdem der (an den Enden bereinigte) Text an Leerraum getrennt wurde (`/\s+/`).
- **Zeichen** = Anzahl der Graphem-Cluster, also der Zeichen, die ein Mensch zählen würde, über `Intl.Segmenter`; Browser ohne Unterstützung zählen Unicode-Codepoints. Leerzeichen und Zeilenumbrüche zählen mit.
- **Zeilen** = Anzahl der durch Umbrüche getrennten Zeilen. Ein leeres Feld zeigt 0, ein abschließender Umbruch fügt eine leere letzte Zeile hinzu.
- **Lesezeit** = ⌈Wörter ÷ 200 × 60⌉ Sekunden, unter einer Minute in Sekunden, darüber in aufgerundeten Minuten.

Jede Schaltfläche wendet eine Umwandlung auf den ganzen Text an und zählt dann neu:

| Schaltfläche | Wirkung | Beispiel |
|---|---|---|
| **Großbuchstaben** | Unicode-Großschreibung (`toUpperCase`) | `straße` → `STRASSE` |
| **Kleinbuchstaben** | Unicode-Kleinschreibung (`toLowerCase`) | `HaLLo` → `hallo` |
| **Duplikate entfernen** | Behält die erste Kopie jeder identischen Zeile, in Reihenfolge | `a, b, a, c` → `a, b, c` |
| **Leerzeichen entf.** | Trimmt jede Zeile, erlaubt höchstens eine Leerzeile am Stück, trimmt die Enden | `··Text··` → `Text` |
| **Hacker-Modus** | Ersetzt a→4, b→8, e→3, g→9, i→1, l→1, o→0, s→5, t→7 | `get root` → `937 r007` |
| **Kopieren** | Kopiert den Text über die Clipboard-API | — |

Zwei nützliche Details: Die Umwandlung ist nicht sprachspezifisch, das türkische *i* mit und ohne Punkt folgt also den allgemeinen Unicode-Regeln. Leerzeichen entf. wirkt nur auf Zeilenenden und Leerzeilen; doppelte Leerzeichen *innerhalb* einer Zeile bleiben, damit Code-Einrückungen und Tabellen lesbar bleiben.

## Anwendungsfälle

- **Schreiben mit Limit.** Prüfen Sie Aufsätze, Meta-Descriptions, Abstracts oder Social-Media-Posts beim Bearbeiten gegen ein Wort- oder Zeichenbudget.
- **Listen bereinigen.** Fügen Sie eine aus einer Tabelle exportierte Spalte mit E-Mails, Hostnamen oder IDs ein und entfernen Sie Duplikate per Klick; E-Mail-Adressen vorher in Kleinbuchstaben umwandeln.
- **Logs und eingefügte Ausgaben aufräumen.** Entfernen Sie Leerzeichen am Zeilenende und überflüssige Leerzeilen aus Terminal-Ausgaben, bevor sie in ein Ticket oder Dokument wandern.
- **Bezeichner normalisieren.** Tags oder Schlüssel vor dem Vergleich in Kleinbuchstaben umwandeln, Konstanten und SQL-Schlüsselwörter in Großbuchstaben.
- **Spaßtext.** Verwandeln Sie einen Nutzernamen, ein Banner oder Ihren CTF-Teamnamen in Leetspeak.
- **Redezeit abschätzen.** Die Lesezeit ist ein grober Richtwert für Manuskripte; gesprochen wird langsamer, meist etwa 130–150 Wörter pro Minute.

Um Text zu kodieren statt umzuformen, nutzen Sie den [Base64-Konverter](/de/tools/base64-converter/) oder den [Hash-Generator](/de/tools/hash-generator/).
