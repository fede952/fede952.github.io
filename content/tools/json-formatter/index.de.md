---
title: "JSON-Formatter und -Validator, JSON in YAML"
description: "JSON formatieren, minimieren und mit genauer Zeilen- und Spaltenangabe prüfen, Schlüssel sortieren, als Baum ansehen, in YAML oder CSV umwandeln. Privat."
intro: "Fügen Sie JSON ein, um es mit 2 oder 4 Leerzeichen oder Tabs zu **formatieren**, zu **minimieren**, mit genauer *Zeile und Spalte* des ersten Fehlers zu **validieren**, **Schlüssel zu sortieren**, es als aufklappbaren **Baum** anzusehen oder **JSON in YAML**, **YAML in JSON** und **JSON in CSV** umzuwandeln. Dateien mit mehreren Megabyte verarbeitet ein Hintergrund-Worker; hochgeladen wird nichts."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["json formatter", "json validator", "json formatieren online", "json beautifier", "json in yaml", "yaml in json", "json in csv", "json minimieren"]
tags: ["entwickler-tools", "json", "yaml", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-formatter/"
tool_title: "JSON-Formatter, -Validator und -Konverter"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Fügen Sie Ihr JSON in **Eingabe** ein, öffnen Sie eine `.json`-Datei mit **Datei öffnen** oder klicken Sie zum Ausprobieren auf **Beispiel**."
  - "Klicken Sie auf **Formatieren** (oder Strg/⌘ + Eingabe), um es mit der gewählten **Einrückung** auszugeben; **Minimieren** entfernt alle Leerzeichen. Mit **Schlüssel sortieren** werden die Schlüssel jedes Objekts alphabetisch geordnet."
  - "Ist das JSON ungültig, nennt die Statuszeile das Problem und seine Position – etwa *Zeile 3, Spalte 14: abschließendes Komma* – und zeigt die betroffene Zeile mit einer Markierung unter dem genauen Zeichen."
  - "Wandeln Sie mit **In YAML** oder **In CSV** um (wählen Sie das **CSV-Trennzeichen**). Für den umgekehrten Weg wechseln Sie zu **YAML-Eingabe**, fügen YAML ein und klicken auf **Formatieren**, um JSON zu erhalten."
  - "Schalten Sie die Ausgabe zwischen **Text** und **Baum** um, um große Strukturen zu durchsuchen, und **Kopieren** oder **Herunterladen** Sie das Ergebnis."
faq:
  - q: "Wird mein JSON an einen Server gesendet?"
    a: "Nein. Parsen, Formatieren und Umwandeln laufen in Ihrem Browser – Eingaben über 2 MB in einem Web Worker im selben Tab. Die Seite stellt keine Anfrage mit Ihren Daten; API-Antworten, Tokens und Konfigurationsdateien bleiben auf Ihrem Rechner."
  - q: "Warum heißt es „abschließendes Komma“?"
    a: "JSON erlaubt kein Komma nach dem letzten Element eines Objekts oder Arrays, auch wenn JavaScript das tut. `[1, 2,]` und `{\"a\": 1,}` sind ungültiges JSON; entfernen Sie das letzte Komma. Weitere häufige Fehler, die der Validator benennt: einfache Anführungszeichen, Schlüssel ohne Anführungszeichen, Kommentare sowie NaN oder Infinity."
  - q: "Wie findet das Tool Zeile und Spalte eines Fehlers?"
    a: "Die Meldungen von JSON.parse unterscheiden sich je nach Browser, manche nennen nur eine Zeichenposition. Schlägt das Parsen fehl, liest das Tool den Text mit einem eigenen strengen Scanner nach RFC 8259 erneut, der beim ersten Zeichen stoppt, das in gültigem JSON unmöglich ist, und dessen Zeile und Spalte meldet."
  - q: "Wie wird JSON in CSV umgewandelt?"
    a: "Ein Array aus Objekten ergibt eine Zeile pro Objekt. Verschachtelte Objekte werden zu Spalten mit Punkt (`address.city`), Arrays innerhalb einer Zeile werden als JSON-Text geschrieben, und die Spalten sind die Vereinigung aller Schlüssel in der Reihenfolge ihres ersten Auftretens. Werte mit Kommas, Anführungszeichen oder Zeilenumbrüchen werden nach RFC 4180 in Anführungszeichen gesetzt. Ein Array aus Arrays wird zeilenweise geschrieben."
  - q: "Bleiben YAML-Kommentare und -Anker bei der Umwandlung erhalten?"
    a: "Von YAML nach JSON werden Anker und Aliase in normale Werte aufgelöst, Kommentare gehen verloren, weil JSON beides nicht kennt. Von JSON nach YAML entsteht YAML im Blockstil ohne Anker, wiederholte Strukturen werden also vollständig ausgeschrieben."
  - q: "Verändert das Sortieren der Schlüssel meine Daten?"
    a: "Kein Wert ändert sich. Objektschlüssel werden auf allen Ebenen nach Unicode-Codepunkt sortiert (Großbuchstaben vor Kleinbuchstaben); Arrays behalten ihre Reihenfolge, weil diese Teil der Daten ist. Sortierte Ausgabe ist praktisch für Diffs und stabile Dateien in der Versionsverwaltung."
  - q: "Wie groß darf eine Datei sein?"
    a: "Einige Dutzend Megabyte auf einem Computer. Ab 2 MB laufen Formatieren und Minimieren in einem Hintergrund-Worker, damit die Seite reagiert. Die Baumansicht erzeugt Knoten erst beim Aufklappen und zeigt höchstens 500 Kinder pro Knoten auf einmal."
---

## So funktioniert es

### Eine Validierung, die sich erklärt

Die Eingabe wird mit dem nativen `JSON.parse` des Browsers geparst, dem schnellsten und standardtreuesten verfügbaren Parser. Schlägt es fehl, durchläuft ein zweiter, bewusst kleiner Scanner den Text nach der Grammatik von RFC 8259 – Objekte, Arrays, Strings mit ihren Escape-Regeln, Zahlen ohne führende Nullen, `true`, `false`, `null` – und hält beim ersten Zeichen an, mit dem kein gültiges Dokument weitergehen kann. Diese Position wird in Zeile und Spalte umgerechnet und mit einer verständlichen Erklärung verknüpft: ein abschließendes Komma, ein fehlender Doppelpunkt, ein String in einfachen Anführungszeichen, ein nicht maskierter Tab in einem String oder Text nach dem Ende des Dokuments.

### Formatieren, minimieren und sortieren

Formatiert wird mit `JSON.stringify` und der gewählten Einrückung (2 Leerzeichen, 4 Leerzeichen oder ein Tab). Minimieren schreibt dieselbe Struktur ohne Leerraum. **Schlüssel sortieren** baut jedes Objekt vor dem Serialisieren mit Schlüsseln in Codepunkt-Reihenfolge neu auf; die Reihenfolge von Arrays wird nie geändert. Zahlen werden so geschrieben, wie JavaScript sie liest; Ganzzahlen über 2^53 verlieren daher an Genauigkeit – solche IDs besser als Strings speichern.

### Große Eingaben

Ab 2 MB UTF-8 übernimmt ein **Web Worker**, ein Hintergrund-Thread im selben Tab, das Formatieren und Minimieren, damit Tippen und Scrollen flüssig bleiben, während ein großer API-Dump verarbeitet wird. Die Baumansicht entsteht bei Bedarf: Die Kinder eines Knotens werden erst beim Aufklappen erzeugt.

### Umwandlungen

Die YAML-Unterstützung stammt von **js-yaml** (MIT), wird von dieser Website ausgeliefert und erst bei der ersten Verwendung von YAML geladen. YAML wird mit dem sicheren Standardschema gelesen, kann also keine eigenen Objekte erzeugen oder Code ausführen. CSV erzeugt das Tool selbst, mit Quoting und Zeilenenden nach RFC 4180.

## Anwendungsfälle

- **APIs debuggen.** Eine einzeilige Antwort lesbar machen, das gesuchte Feld im Baum finden oder genau sehen, wo ein von Hand bearbeiteter Payload kaputtgeht.
- **Konfiguration.** Ein Kubernetes- oder Docker-Compose-Snippet zwischen YAML und JSON umwandeln oder eine `package.json` bzw. `tsconfig.json` nach dem Bearbeiten prüfen.
- **Datenexporte.** Ein Array von Datensätzen als CSV für eine Tabellenkalkulation ausgeben, mit verschachtelten Feldern als Spalten.
- **Code-Review und Versionsverwaltung.** Schlüssel sortieren und einheitlich formatieren, damit Diffs echte Änderungen zeigen statt Umsortierungen.
- **Sensible Daten.** JWT-Payloads, Webhook-Bodies oder Logs mit personenbezogenen Daten prüfen, ohne sie auf einer fremden Website einzufügen.
