---
title: "EXIF-Daten & GPS aus Fotos entfernen"
description: "Sehen Sie die versteckten EXIF-Metadaten eines Fotos (GPS-Position, Kamera, Datum) und laden Sie eine bereinigte Kopie herunter – offline im Browser."
intro: "**EXIF Cleaner** zeigt die in einem Foto versteckten Metadaten (GPS-Koordinaten, Kameramodell, Aufnahmedatum, Software) und liefert eine bereinigte Kopie ohne all das. Das Bild verlässt Ihr Gerät nie."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["exif daten entfernen", "metadaten aus foto entfernen", "gps aus foto entfernen", "standort aus bild löschen", "exif viewer", "exif entfernen online", "foto metadaten anzeigen", "exif remover"]
tags: ["datenschutz", "osint", "bilder", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/exif-cleaner/"
tool_title: "EXIF Cleaner: Metadaten anzeigen und entfernen"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Ziehen Sie ein Foto in die Ablagefläche oder klicken Sie, um eines auszuwählen. JPEG funktioniert am besten; PNG und WebP werden ebenfalls akzeptiert."
  - "Lesen Sie die Tabelle **Metadaten Gefunden**: Kamerahersteller und -modell, Aufnahmedatum, Software, Belichtung, ISO, Brennweite, Ausrichtung, Abmessungen, Copyright, Urheber und GPS-Koordinaten."
  - "Erscheint ein roter Hinweis, enthält das Foto eine **GPS-Position**. Die angezeigten Dezimalkoordinaten markieren den Aufnahmeort auf wenige Meter genau."
  - "Klicken Sie auf **Metadaten Entfernen & Herunterladen**. Das Bild wird ohne jegliche Metadaten neu gezeichnet und im gleichen Format gespeichert."
  - "Mit **Bereinigtes Bild Herunterladen** speichern Sie `ihredatei-clean.jpg` (oder .png/.webp) – teilen Sie diese Kopie statt des Originals."
faq:
  - q: "Was sind EXIF-Daten?"
    a: "EXIF (Exchangeable Image File Format) ist ein Metadatenblock, den Kameras und Smartphones in jedes Foto schreiben: Gerätehersteller und -modell, Objektiv, Belichtungswerte, Datum und Uhrzeit, die Bearbeitungssoftware und oft die GPS-Koordinaten des Aufnahmeorts. Beim Betrachten unsichtbar, mit Tools wie diesem aber in Sekunden auslesbar."
  - q: "Entfernen soziale Netzwerke EXIF automatisch?"
    a: "Große Plattformen wie Facebook, Instagram, X und WhatsApp entfernen die meisten Metadaten aus veröffentlichten Bildern. E-Mail-Anhänge, Cloud-Links, Foren, Kleinanzeigenportale, Dating-Apps und viele Messenger beim Versand „als Datei“ oder „in Originalqualität“ tun das nicht. Im Zweifel bereinigen Sie das Foto vorher."
  - q: "Wird mein Foto zum Entfernen der Metadaten hochgeladen?"
    a: "Nein. Das Auslesen der Metadaten und das Erstellen der bereinigten Kopie passieren per JavaScript in dieser Seite. Nach dem Laden können Sie die Internetverbindung trennen – das Tool funktioniert weiter und eignet sich daher auch für sensible Fotos."
  - q: "Verringert das Bereinigen die Bildqualität?"
    a: "PNG-Ausgaben sind verlustfrei. JPEG und WebP werden mit Qualität 95 neu kodiert, was bei fast allen Fotos nicht vom Original zu unterscheiden ist; die Dateigröße kann sich leicht ändern. Die Auflösung bleibt exakt gleich."
  - q: "Warum zeigt mein PNG oder WebP keine Metadaten?"
    a: "Der Viewer nutzt exif-js, das den EXIF-Block von JPEG-Dateien liest. PNG und WebP speichern Metadaten anders und enthalten selten GPS-Daten, daher kann die Tabelle leer bleiben. Die bereinigte Kopie wird trotzdem aus den Pixeln neu kodiert, also verschwinden auch dort eventuell vorhandene Metadaten."
  - q: "Ist das bereinigte Foto noch richtig herum?"
    a: "Ja. Smartphones speichern Fotos oft seitlich und verlassen sich auf das EXIF-Tag Orientation zum Drehen. Der Browser wendet diese Drehung beim Zeichnen an, sodass die bereinigte Kopie die richtige Ausrichtung direkt in den Pixeln hat und das Tag nicht mehr braucht."
  - q: "Lassen sich entfernte Metadaten aus der Kopie wiederherstellen?"
    a: "Nein. Die bereinigte Datei ist ein neues Bild, das nur aus Pixeln besteht; der ursprüngliche Metadatenblock wird nie hineinkopiert. Behalten Sie das Original, wenn Sie Datum und Ort für Ihr eigenes Fotoarchiv brauchen."
---

## So funktioniert es

### Metadaten auslesen

Wenn Sie eine Datei ablegen, liest die Seite sie lokal mit `FileReader` und übergibt sie an **exif-js** (v2.3.0, hier selbst gehostet). Die Bibliothek durchläuft das APP1-Segment des JPEG und dekodiert die TIFF-strukturierten EXIF-Verzeichnisse: das Hauptverzeichnis des Bildes (Hersteller, Modell, Software, Ausrichtung, Copyright, Urheber), das Exif-Unterverzeichnis (Belichtungszeit, Blende, ISO, Brennweite, Blitz, Pixelmaße, Farbraum) und das GPS-Verzeichnis.

GPS-Koordinaten werden in Grad, Minuten und Sekunden plus Hemisphären-Angabe (N/S, E/W) gespeichert. Das Tool rechnet sie in Dezimalgrad um, `Grad + Minuten/60 + Sekunden/3600`, negativ für Süd und West, und zeigt sie mit sechs Nachkommastellen an – das entspricht etwa 10 cm. Ist eine GPS-Position vorhanden, erscheint der rote Hinweis.

### Die bereinigte Kopie erstellen

Die Metadaten werden nicht Byte für Byte herausgeschnitten: Das Tool verwirft den kompletten Container.

1. Der Browser dekodiert das Bild in rohe Pixel.
2. Diese Pixel werden in voller Auflösung auf ein HTML-`<canvas>` gezeichnet. Dabei wendet der Browser die EXIF-Ausrichtung an, das Ergebnis steht also richtig herum.
3. Das Canvas wird mit `canvas.toBlob()` in eine völlig neue Datei kodiert: **JPEG mit Qualität 0,95** für JPEG-Eingaben, **WebP mit 0,95** für WebP und **PNG** für alles andere.

Ein Canvas enthält nur Pixel, daher hat die neue Datei **kein EXIF, kein GPS, keine XMP- oder IPTC-Tags, kein eingebettetes Vorschaubild** (alte Vorschaubilder zeigen manchmal noch das *unbeschnittene* Original) und kein Farbprofil. Bilder werden in sRGB ausgegeben; Fotos mit großem Farbraum können dadurch minimal weniger gesättigt wirken.

Zur Kontrolle ziehen Sie die heruntergeladene `-clean`-Datei einfach erneut in das Tool: Die Tabelle bleibt leer, und kein GPS-Hinweis erscheint.

### Was es nicht verändert

Die bereinigte Kopie entfernt *Metadaten*, nicht das, was auf dem Bild zu sehen ist. Ein Straßenschild, eine Spiegelung im Schaufenster, ein Nummernschild oder ein bekanntes Wahrzeichen können den Aufnahmeort trotzdem verraten. Beschneiden oder verpixeln Sie solche Details vor dem Teilen.

## Anwendungsfälle

- **Online verkaufen.** Fotos von Gegenständen, die zu Hause entstanden sind, können die GPS-Koordinaten Ihrer Wohnung enthalten. Bereinigen Sie sie, bevor Sie sie auf ein Kleinanzeigenportal laden.
- **Bilder an Menschen schicken, die Sie kaum kennen** – Vermieter, Dating-Kontakte, Käufer –, ohne Adresse und Handymodell preiszugeben.
- **Journalismus und Aktivismus.** Entfernen Sie Standort und Gerätedetails aus Bildern, die eine Quelle identifizieren könnten.
- **Prüfen, was Sie teilen.** Öffnen Sie ein Foto und sehen Sie genau, was es verrät – die eigene Straße zum ersten Mal auf einer Karte zu sehen, ist oft ein Aha-Erlebnis.
- **OSINT üben.** Ermittler nutzen EXIF als Spur. Verwenden Sie den Viewer mit Beispielbildern, um zu lernen, was sich auslesen lässt und warum Bereinigen wichtig ist.
