---
title: "Screenshot schwärzen: Text abdecken"
description: "Decken Sie E-Mails, Namen, IBANs und andere sensible Teile eines Screenshots ab. Volle Flächen fest in die Pixel eingebrannt, ohne Metadaten, im Browser."
intro: "Fügen Sie einen Screenshot ein (Strg+V), ziehen Sie ein Bild hinein oder wählen Sie es aus, und **ziehen Sie dann über alles Sensible**: E-Mail-Adressen, Namen, Kontonummern, Gesichter, URLs. Die Abdeckungen sind **volle Flächen, fest in die Pixel eingebrannt** – keine Ebenen, die man entfernen könnte – und das exportierte PNG oder JPEG enthält **keine Metadaten**. Eine optionale Hilfe kann **Flächen vorschlagen** über E-Mails, IBANs, Karten- und Telefonnummern und IP-Adressen. Nichts wird hochgeladen."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["screenshot schwärzen", "text in bild schwärzen", "bild schwärzen online", "sensible daten im screenshot verbergen", "screenshot zensieren", "bild verpixeln online", "bild unkenntlich machen", "persönliche daten im screenshot entfernen"]
tags: ["datenschutz", "bilder", "sicherheit", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/screenshot-redactor/"
tool_title: "Screenshot schwärzen"
tool_height: 1050
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write; clipboard-read"
howto:
  - "Fügen Sie einen Screenshot mit **Strg+V** (⌘V am Mac) ein, ziehen Sie ein Bild auf das Feld oder klicken Sie auf **Bild auswählen**."
  - "Lassen Sie **Volle Fläche** ausgewählt (standardmäßig schwarz; wählen Sie bei Bedarf eine andere **Farbe**) und ziehen Sie über jeden Bereich, der verschwinden soll. Am Smartphone mit einem Finger ziehen und mit **Verschieben** in einem vergrößerten Bild scrollen."
  - "Optional: Mit **Bereiche vorschlagen** findet die Texterkennung auf Ihrem Gerät E-Mails, IBANs, Kartennummern, Telefonnummern und IP-Adressen. Entfernen Sie den Haken bei Vorschlägen, die sichtbar bleiben sollen, und **decken** Sie den Rest ab."
  - "Prüfen Sie mit **Rückgängig** / **Wiederholen** (Strg+Z / Strg+Y) und den Zoom-Schaltflächen die Ränder jeder Fläche."
  - "Wählen Sie **PNG** (scharfer Text) oder **JPEG** (kleinere Fotos) und klicken Sie auf **Geschwärztes Bild herunterladen** – oder **Bild kopieren**, um es direkt in einen Chat oder ein Ticket einzufügen."
faq:
  - q: "Wird mein Bild irgendwohin hochgeladen?"
    a: "Nein. Das Bild wird in Ihrem Browser dekodiert, bearbeitet und exportiert. Auch die optionale Texterkennung läuft auf Ihrem Gerät; beim ersten Mal lädt sie ihre Erkennungsdateien (etwa 10 MB) von dieser Website, nie von Dritten, und das Bild selbst wird nirgendwohin gesendet."
  - q: "Warum ist eine volle Fläche sicherer als Weichzeichnen oder Verpixeln?"
    a: "Eine volle Fläche ersetzt die Pixel durch eine einzige Farbe: Vom Original bleibt nichts übrig. Weichzeichnen und Verpixeln behalten eine verkleinerte Fassung der Originalpixel. Bei kurzen oder vorhersehbaren Texten – Zahlen, Kartenziffern, Namen in einer bekannten Schrift – reicht das manchmal, um sie zu rekonstruieren oder zu erraten, etwa indem man Kandidatentexte genauso verpixelt oder weichzeichnet und die Ergebnisse vergleicht. Nutzen Sie diese Modi nur für Dinge, die lediglich weniger auffallen sollen."
  - q: "Lässt sich die Schwärzung aus der heruntergeladenen Datei entfernen?"
    a: "Nein. Der Export ist ein neues Bild, gezeichnet aus den bearbeiteten Pixeln: keine Ebenen, kein verstecktes Original, kein Bearbeitungsverlauf in der Datei. Das ist der Unterschied zum Abdecken von Text mit einer Form in einem Dokument oder PDF, wo sich der Text darunter oft noch markieren lässt."
  - q: "Werden EXIF- und GPS-Daten entfernt?"
    a: "Ja. Das exportierte PNG oder JPEG wird vom Browser neu kodiert und enthält keine Metadaten: kein Kameramodell, kein Datum, keine GPS-Position. Die Ausrichtung des Fotos wird vorher auf die Pixel angewendet, sodass das Bild richtig herum bleibt."
  - q: "Was findet der automatische Vorschlag?"
    a: "E-Mail-Adressen, IBANs (geprüft über ihre Mod-97-Prüfsumme), Kartennummern (geprüft mit dem Luhn-Algorithmus), Telefonnummern sowie IPv4- und IPv6-Adressen. Er arbeitet mit Bildschirmtext in lateinischer Schrift. Namen, Gesichter, Anschriften oder Handschrift erkennt er nicht – prüfen Sie das Bild vor dem Teilen also immer auch selbst."
  - q: "Welche Bildformate kann ich öffnen?"
    a: "Alles, was Ihr Browser anzeigen kann: PNG, JPEG, WebP, GIF (erstes Bild) und meist auch AVIF und BMP. HEIC-Fotos vom iPhone müssen vorher umgewandelt werden, zum Beispiel mit dem HEIC-Konverter auf dieser Website."
---

## So funktioniert es

### Abdeckungen sind Pixel, keine Ebenen

Das Bild wird in voller Auflösung in ein Canvas dekodiert, mit angewandter EXIF-Ausrichtung des Fotos. Jede gezeichnete Fläche wird als Rechteck gespeichert, und das Gesamtbild aus Original plus allen Flächen wird bei jedem Zeichnen, Rückgängigmachen oder Wiederholen aus den Originalpixeln neu aufgebaut. Beim Export wird dieses Gesamtbild in ein völlig neues PNG oder JPEG kodiert. Die Datei enthält nur die endgültigen Pixel: Was unter einer Fläche lag, existiert darin nicht mehr.

Genau deshalb scheitern Schwärzungen in Textprogrammen so oft: Ein schwarzes Rechteck über Text in einem Dokument oder PDF ist ein eigenes Objekt, und der Text darunter lässt sich weiterhin markieren oder auslesen. Hier ist darunter nichts.

### Warum Weichzeichnen und Verpixeln eine Warnung tragen

Verpixeln ersetzt jeden Pixelblock durch seine Durchschnittsfarbe; Weichzeichnen verteilt jedes Pixel auf seine Nachbarn. Beides verwirft Information, aber nicht alle. Bei Text beeinflusst die Form jedes Buchstabens das Ergebnis weiterhin, und die möglichen Originale sind oft wenige: Eine Kartennummer hat pro Stelle nur zehn mögliche Ziffern, und Screenshots verwenden eine Handvoll bekannter Schriften. Man kann Kandidatentexte in derselben Schrift setzen, sie genauso verpixeln oder weichzeichnen und den passenden behalten. Öffentliche Tools und Forschungsarbeiten haben gezeigt, dass das bei verpixelten Passwörtern und Zahlen funktioniert. Eine volle Fläche lässt nichts zum Vergleichen übrig – deshalb ist sie die Voreinstellung und der einzige empfohlene Modus für Geheimes.

### Die optionalen Vorschläge

Die Texterkennung nutzt Tesseract, eine quelloffene OCR-Engine, kompiliert zu WebAssembly und von dieser Website ausgeliefert. Sie wird erst geladen, wenn Sie **Bereiche vorschlagen** anklicken. Die erkannten Wörter werden mit Mustern für E-Mails, IBANs, Kartennummern, Telefonnummern und IP-Adressen abgeglichen; IBANs und Kartennummern müssen zusätzlich ihre Prüfziffer bestehen, was Fehlalarme reduziert. Jeder Treffer wird zu einem gestrichelten Vorschlag, den Sie annehmen oder verwerfen können.

## Anwendungsfälle

- **Fehlerberichte und Support-Tickets** – den Screenshot eines Fehlers teilen, ohne E-Mail-Adresse, Konto-ID oder API-Schlüssel.
- **Soziale Netzwerke und Foren** – ein Gespräch oder einen Beleg posten, mit abgedeckten Namen, Telefon- und Bestellnummern.
- **Dokumentation und Tutorials** – interne URLs, IP-Adressen und Kundendaten in Screenshots von Admin-Oberflächen verbergen.
- **Spesenabrechnungen** – das Foto einer Quittung oder Überweisung mit geschwärzter Kontonummer senden.
- **Sicherheitsarbeit** – Belege in einen Bericht aufnehmen, ohne die enthaltenen Zugangsdaten oder personenbezogenen Daten preiszugeben.
