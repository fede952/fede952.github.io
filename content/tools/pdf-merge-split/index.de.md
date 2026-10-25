---
title: "PDF zusammenfügen und teilen, kostenlos"
description: "PDF-Dateien zusammenfügen, nach Seiten oder Bereichen teilen, Seiten sortieren, drehen und löschen – im Browser. Ihre PDFs werden nie hochgeladen. Kostenlos."
intro: "**PDFs zusammenfügen**, **ein PDF teilen** – in einzelne Seiten oder Seitenbereiche – und dabei Seiten sortieren, drehen oder löschen, mit Vorschaubildern, die Sie ziehen können. Alles geschieht in diesem Browser-Tab: Verträge, Gehaltsabrechnungen und Scans verlassen Ihr Gerät nie."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["pdf zusammenfügen", "pdf teilen", "pdf dateien zusammenführen", "pdf seiten sortieren", "pdf online teilen", "pdf zusammenfügen ohne upload", "seiten aus pdf extrahieren", "pdf seiten drehen"]
tags: ["pdf", "datenschutz", "dokumente", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/pdf-merge-split/"
tool_title: "PDF zusammenfügen, teilen und sortieren"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Ziehen Sie eine oder mehrere PDF-Dateien in das Feld oder klicken Sie, um sie auszuwählen. Jede Seite erscheint als nummeriertes Vorschaubild, in der Reihenfolge der Dateien."
  - "Ordnen Sie die Seiten: Ziehen Sie ein Vorschaubild an eine neue Stelle oder nutzen Sie die Schaltflächen **←** und **→** (praktisch auf dem Handy). **⟳** dreht eine Seite um 90°, **✕** lässt sie im Ergebnis weg."
  - "Zum Zusammenfügen geben Sie den **Dateiname** ein und klicken auf **Zusammenfügen und herunterladen**: Sie erhalten ein PDF mit den Seiten genau in Ihrer Anordnung."
  - "Zum Teilen wählen Sie **Jede Seite als eigenes PDF** oder **Nach Seitenbereichen** und geben Gruppen wie `1-3, 4, 5-` ein (die Nummern der Vorschaubilder; `5-` bedeutet ab Seite 5 bis zum Ende)."
  - "Klicken Sie auf **Teilen und herunterladen (.zip)**. Jede Gruppe wird ein PDF, benannt nach der ersten Datei (`bericht-part-1.pdf` …); bei nur einer Gruppe erhalten Sie das PDF direkt."
faq:
  - q: "Werden meine PDFs irgendwohin hochgeladen?"
    a: "Nein. Der Browser liest die Dateien, zeigt sie mit pdf.js in der Vorschau an und baut sie mit pdf-lib neu auf; beides läuft in diesem Tab. Die Seite lädt diese Bibliotheken einmal und sendet nichts zurück – das können Sie im Netzwerk-Panel beim Zusammenfügen prüfen."
  - q: "Verliert das Zusammenfügen an Qualität?"
    a: "Nein. Die Seiten werden unverändert kopiert: Text bleibt Text, Bilder behalten ihre ursprüngliche Kompression, Schriften werden übernommen. Nichts wird gerastert oder neu komprimiert, das Ergebnis ist so scharf wie die Originale."
  - q: "Kann ich passwortgeschützte PDFs zusammenfügen?"
    a: "Nicht direkt: Ein verschlüsseltes PDF lässt sich ohne Passwort nicht lesen, und das Tool meldet das, statt eine kaputte Datei zu erzeugen. Öffnen Sie es in einem PDF-Reader, speichern Sie eine Kopie ohne Passwort und fügen Sie diese hinzu."
  - q: "Bleiben Links, Lesezeichen und Formularfelder erhalten?"
    a: "Seiteninhalte, Anmerkungen und Links auf den Seiten werden kopiert. Die Gliederung (Lesezeichen) und die Logik interaktiver Formulare gehören zur gesamten Originaldatei und werden im zusammengefügten PDF nicht neu aufgebaut – prüfen Sie Formulare danach."
  - q: "Wie groß dürfen die Dateien sein?"
    a: "Es gibt keine feste Grenze; entscheidend ist der Arbeitsspeicher. Dokumente mit einigen hundert Seiten funktionieren auf einem Computer gut. Für jede Seite wird ein Vorschaubild erzeugt, sehr große Dateien erscheinen daher langsamer."
  - q: "Was macht das Drehen mit der Datei?"
    a: "Es setzt die Seitendrehung im PDF (in 90°-Schritten), die jeder Reader beachtet. Der Inhalt wird nicht neu gezeichnet, das Drehen ist also verlustfrei und lässt sich durch erneutes Drehen rückgängig machen."
  - q: "Wie extrahiere ich nur einige Seiten?"
    a: "Wählen Sie **Nach Seitenbereichen** mit einer einzigen Gruppe, zum Beispiel `3-5`: Sie laden ein PDF herunter, das nur die Seiten 3, 4 und 5 enthält. Alternativ entfernen Sie die unerwünschten Seiten mit ✕ und fügen zusammen."
---

## So funktioniert es

### Zwei Bibliotheken, beide lokal

Ein PDF lesen und eines schreiben sind getrennte Aufgaben, daher nutzt das Tool zwei Open-Source-Bibliotheken, die von dieser Website ausgeliefert und erst beim Hinzufügen einer Datei geladen werden:

- **pdf.js** (Mozilla, Apache-2.0), der Kern des PDF-Viewers von Firefox, erzeugt in einem Hintergrund-Worker ein kleines Vorschaubild jeder Seite, damit die Seite reaktionsfähig bleibt.
- **pdf-lib** (MIT) erstellt das Ergebnis. Für jede Seite in Ihrer Reihenfolge kopiert es das Seitenobjekt aus dem Quelldokument – Inhaltsströme, Schriften, Bilder und Anmerkungen – mit `copyPages` in ein neues Dokument, wendet die gewählte Drehung an und speichert.

Vorab prüft das Tool, ob jede Datei mit `%PDF-` beginnt; ein umbenanntes Word-Dokument oder ein beschädigter Download wird mit seinem Namen gemeldet.

### Seitenreihenfolge und Bereiche

Die Vorschaubilder bilden eine einzige Liste über alle Dateien: Beim Zusammenfügen werden sie in dieser Reihenfolge geschrieben, und auch die Nummern für das Teilen beziehen sich darauf. Bereiche sind durch Kommas getrennte Gruppen; jede Gruppe kann eine einzelne Seite (`4`), ein Bereich (`1-3`), ein offenes Ende (`5-` bis zur letzten Seite) oder ein offener Anfang (`-3`) sein. Jede Gruppe wird ein PDF; mehrere PDFs werden mit JSZip in ein ZIP gepackt.

### Was nicht übernommen wird

Das neue Dokument erhält von pdf-lib frische Metadaten statt der Titel und Autoren der Quellen, und dokumentweite Funktionen wie die Lesezeichen-Gliederung und Formularskripte werden nicht neu erstellt. Für das alltägliche Zusammenfügen und Teilen – Rechnungen, Scans, Kapitel, Folien – ist das genau richtig.

## Anwendungsfälle

- **Scans zusammenführen**: einen mehrseitigen Vertrag oder ein Formular vor dem Versand per E-Mail zu einer Datei machen.
- **Ein großes PDF teilen** – ein Lehrbuch, ein Handbuch, ein Jahr Kontoauszüge – in Kapitel oder Monate.
- **Seiten entfernen**, die persönliche Daten enthalten, bevor Sie ein Dokument weitergeben.
- **Reihenfolge und Ausrichtung korrigieren** bei einem Dokument, das verkehrt herum oder durcheinander gescannt wurde.
- **Bewerbungsunterlagen zusammenstellen**: Lebenslauf, Anschreiben und Zeugnisse in der gewünschten Reihenfolge – ohne sie einem Onlinedienst zu überlassen, über den Sie nichts wissen.
