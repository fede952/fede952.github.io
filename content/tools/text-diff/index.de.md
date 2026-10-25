---
title: "Textvergleich online: Unterschiede finden"
description: "Zwei Texte oder Dateien nebeneinander oder untereinander vergleichen, Wörter oder Zeichen markieren, Leerraum ignorieren und Unified Diff kopieren. Privat."
intro: "Fügen Sie zwei Versionen eines Textes, einer Konfigurationsdatei oder eines Code-Stücks ein und sehen Sie jede **hinzugefügte**, **entfernte** und **geänderte** Zeile – **nebeneinander** oder **untereinander**, mit den geänderten **Wörtern** oder **Zeichen** hervorgehoben. Leerraum oder Groß-/Kleinschreibung ignorieren, unveränderte Zeilen einklappen und einen **Unified Diff kopieren**, der sich mit `git apply` oder `patch` anwenden lässt. Nichts verlässt Ihren Browser."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["textvergleich", "texte vergleichen", "diff online", "unterschiede finden text", "dateien vergleichen", "unified diff", "text compare", "zwei texte vergleichen"]
tags: ["entwickler-tools", "diff", "text", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/text-diff/"
tool_title: "Textvergleich (Diff)"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Fügen Sie die alte Version in **Original** und die neue in **Geändert** ein oder laden Sie beide mit **Datei öffnen**. Mit **Beispiel** probieren Sie es an zwei Versionen einer nginx-Konfiguration aus."
  - "Das Ergebnis aktualisiert sich beim Tippen. Wählen Sie **Nebeneinander** für zwei Spalten oder **Untereinander** für eine Spalte mit −- und +-Zeilen (Standard auf Smartphones)."
  - "Stellen Sie **Markieren** auf **Wörter** oder **Zeichen**, um festzulegen, wie genau Änderungen innerhalb einer geänderten Zeile markiert werden."
  - "Aktivieren Sie **Leerraum ignorieren**, damit Einrückung und mehrfache Leerzeichen als gleich gelten, und **Groß-/Kleinschreibung ignorieren**, um Groß- und Kleinbuchstaben gleich zu behandeln."
  - "Lange unveränderte Abschnitte werden auf drei Kontextzeilen eingeklappt; ein Klick auf eine *⋯ unveränderte Zeilen*-Leiste klappt sie auf. Mit **Unified Diff kopieren** oder **.diff herunterladen** geben Sie die Änderung als Patch weiter."
faq:
  - q: "Werden meine Texte irgendwohin hochgeladen?"
    a: "Nein. Der Vergleich läuft vollständig in Ihrem Browser mit der Open-Source-Bibliothek jsdiff, die von dieser Website ausgeliefert wird. Nichts, was Sie einfügen oder öffnen, wird an einen Server gesendet – Sie können also Verträge, Konfigurationsdateien mit Geheimnissen oder privaten Code vergleichen."
  - q: "Was ist der Unterschied zwischen Wort- und Zeichenmarkierung?"
    a: "In beiden Fällen werden die Texte zuerst zeilenweise zugeordnet. Innerhalb jeder geänderten Zeile markiert der Wortmodus ganze Wörter und abweichende Satzzeichen – am übersichtlichsten für Fließtext und den meisten Code. Der Zeichenmodus markiert einzelne Zeichen und zeigt einen Tippfehler von einem Buchstaben oder eine geänderte Ziffer in einem langen Bezeichner oder einer Zahl."
  - q: "Was genau ignoriert „Leerraum ignorieren“?"
    a: "Leerraum am Zeilenanfang und -ende sowie die Menge an Leerraum zwischen Wörtern: `a  =  1` und `a = 1` gelten als dieselbe Zeile, und neu eingerückte Blöcke erscheinen nicht als geändert. Ein Leerzeichen zwischen zwei vorher zusammengeschriebenen Wörtern bleibt ein Unterschied. Leerzeilen werden weiterhin als Zeilen verglichen."
  - q: "Was ist ein Unified Diff und wie wende ich ihn an?"
    a: "Das Standard-Textformat für eine Änderung, das git, Code-Review-Werkzeuge und patch verwenden: Kopfzeilen mit `---` und `+++`, dann Abschnitte, die mit `@@` beginnen, mit entfernten Zeilen (−) und hinzugefügten Zeilen (+) sowie drei Kontextzeilen. Speichern Sie ihn als `.diff`-Datei und führen Sie `git apply aenderung.diff` oder `patch -p0 < aenderung.diff` aus."
  - q: "Woran erkennt das Tool, dass eine Zeile geändert und nicht entfernt und neu hinzugefügt wurde?"
    a: "Es nutzt den Myers-Diff-Algorithmus auf ganzen Zeilen, um die kleinste Menge an Entfernungen und Hinzufügungen zu finden. Folgen auf einen Block entfernter Zeilen direkt hinzugefügte Zeilen, werden sie eins zu eins als geänderte Zeilen gepaart. Haben zwei Zeilen weniger als etwa 30 % gemeinsam, werden sie als ersetzt gezeigt, ohne Markierungen im Inneren."
  - q: "Kann es große Dateien vergleichen?"
    a: "Ja, bis zu mehreren Megabyte. Texte über etwa 400.000 Zeichen werden beim Klick auf Vergleichen statt bei jedem Tastendruck verglichen. Die Ansicht zeigt bis zu 4.000 Zeilen; der Unified Diff enthält immer das vollständige Ergebnis. Sehr unterschiedliche Texte, die zu lange dauern würden, werden gemeldet, statt die Seite einzufrieren."
  - q: "Kommt es mit Windows-Zeilenenden zurecht?"
    a: "Ja. CRLF- und CR-Zeilenenden werden vor dem Vergleich vereinheitlicht, dieselbe Datei unter Windows und Linux gespeichert gilt also als identisch. Ein fehlender Zeilenumbruch nach der letzten Zeile wird in der Ansicht ignoriert und im Unified Diff vermerkt."
---

## So funktioniert es

### Erst Zeilen, dann Wörter oder Zeichen

Beide Texte werden in Zeilen zerlegt und mit dem **Myers-Diff-Algorithmus** verglichen (dem Verfahren hinter `git diff`), der die kürzeste Folge von Entfernungen und Hinzufügungen findet, die das Original in den geänderten Text überführt. Entfernte Zeilen, auf die direkt hinzugefügte folgen, werden als *geändert* gepaart, und jedes Paar wird erneut Token für Token verglichen: Wörter, Leerraum und einzelne Satzzeichen oder einzelne Zeichen. Hervorgehoben werden nur die abweichenden Token.

### Optionen, die Ihren Text nicht umschreiben

**Leerraum ignorieren** und **Groß-/Kleinschreibung ignorieren** ändern, wie Zeilen und Token *verglichen* werden, nicht was angezeigt wird: Jede Spalte zeigt genau das, was Sie eingefügt haben. So bleibt die Ansicht ehrlich, wenn etwa ein Codeblock neu eingerückt wurde – die Zeilen stimmen überein, und rechts sehen Sie trotzdem die neue Einrückung.

### Unified-Diff-Ausgabe

Die Schaltflächen **Unified Diff kopieren** und **.diff herunterladen** erzeugen einen Standard-Patch mit drei Kontextzeilen, mit den Dateinamen im Kopf, wenn Sie Dateien geöffnet haben (sonst `original.txt` und `changed.txt`). Auf das Original angewendet ergibt er exakt den geänderten Text; die Tests dieses Tools prüfen das mit `git apply`.

## Anwendungsfälle

- **Code und Konfiguration.** Sehen, was sich zwischen zwei Versionen einer nginx-, Docker-Compose- oder YAML-Datei geändert hat, bevor sie live geht – ohne Commit.
- **Dokumente und Verträge.** Jedes geänderte Wort zwischen zwei Entwürfen eines Vertrags, einer Richtlinie oder eines Artikels finden.
- **Logs und Exporte.** Zwei Befehlsausgaben, CSV-Exporte oder Listen vergleichen und neu hinzugekommene oder verschwundene Zeilen erkennen.
- **Änderungen weitergeben.** Die eigene Bearbeitung als `.diff`-Datei verschicken, die ein Kollege mit git anwenden oder in ein Ticket einfügen kann.
- **Copy-and-paste prüfen.** Sicherstellen, dass ein Skript, ein Schlüssel oder ein Snippet ohne unsichtbare Änderungen zwischen Systemen angekommen ist – im Zeichenmodus mit größter Genauigkeit.
