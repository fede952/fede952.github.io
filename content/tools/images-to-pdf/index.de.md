---
title: "JPG in PDF: Bilder kostenlos umwandeln"
description: "JPG-, PNG- und WebP-Bilder im Browser zu einem PDF zusammenfassen: sortieren, drehen, A4, Letter oder Bildgröße und Ränder wählen. Ohne Upload, ohne EXIF."
intro: "Machen Sie aus Fotos, Scans und Screenshots ein einziges **PDF**: Legen Sie **JPG-, PNG-, WebP- oder GIF-Bilder** ab, bringen Sie sie in die richtige Reihenfolge, drehen Sie schiefe Bilder, wählen Sie **A4, US Letter oder die Bildgröße** und einen Rand, und laden Sie herunter. Die Bilder werden in diesem Tab verarbeitet; ihre EXIF- und GPS-Daten landen nie im PDF."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["jpg in pdf", "jpg in pdf umwandeln", "bild in pdf", "png in pdf", "fotos in pdf", "bilder zu pdf zusammenfügen", "jpg in pdf ohne upload", "webp in pdf"]
tags: ["pdf", "bilder", "datenschutz", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/images-to-pdf/"
tool_title: "Bilder-zu-PDF-Konverter"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Ziehen Sie Ihre Bilder in das Feld oder klicken Sie, um sie auszuwählen. Jedes Bild wird eine Seite; weitere können jederzeit dazukommen."
  - "Ordnen Sie die Seiten, indem Sie die Vorschaubilder ziehen oder **←** und **→** verwenden. **⟳** dreht ein Bild um 90°, **✕** entfernt es."
  - "Wählen Sie die **Seitengröße**: **A4**, **US Letter** oder **Wie das Bild** für Seiten, die genau zu jedem Bild passen."
  - "Bei A4 oder Letter legt die Ausrichtung **Automatisch (je Bild)** breite Bilder auf Querformat- und hohe auf Hochformatseiten; Sie können **Hochformat** oder **Querformat** erzwingen. Wählen Sie einen **Rand** (keiner, 1 cm oder 2 cm)."
  - "Geben Sie den **Dateiname** ein und klicken Sie auf **PDF erstellen und herunterladen**."
faq:
  - q: "Werden meine Bilder hochgeladen?"
    a: "Nein. Der Browser dekodiert die Bilder, zeichnet sie auf ein Canvas, und pdf-lib setzt sie in ein PDF – alles in diesem Tab. Nichts wird an einen Server gesendet, was bei Ausweisen, Belegen und Arztbriefen wichtig ist."
  - q: "Enthält das PDF den Standort oder die Kameradaten meiner Fotos?"
    a: "Nein. Jedes Bild wird vor dem Einbetten neu auf ein Canvas gezeichnet, und ein Canvas trägt keine Metadaten. EXIF-Felder wie GPS-Position, Datum und Kameramodell sind daher nicht im PDF. Das PDF selbst erhält nur grundlegende technische Metadaten der Bibliothek."
  - q: "Warum sind meine Handyfotos richtig herum?"
    a: "Handys speichern Fotos oft seitlich und vermerken die richtige Drehung in einem EXIF-Tag. Das Tool liest das Bild mit angewendeter Ausrichtung, bevor es gezeichnet wird; die Seite sieht also aus wie das Foto in Ihrer Galerie. Ist ein Scan noch gedreht, nutzen Sie ⟳."
  - q: "Verlieren die Bilder an Qualität?"
    a: "Fotos werden als hochwertiges JPEG (92 %) neu kodiert, das für Ausdrucke und Dokumente optisch identisch ist. PNG-, WebP- und GIF-Bilder werden verlustfrei als PNG gespeichert, scharfe Schrift und transparente Bereiche bleiben erhalten."
  - q: "Wie groß wird das PDF?"
    a: "Ungefähr so groß wie die hinzugefügten Bilder. Sehr große Fotos ergeben große PDFs; muss die Datei für ein Upload-Formular klein bleiben, komprimieren Sie die Fotos zuerst, etwa mit einem Bildkompressor, und wandeln Sie dann um."
  - q: "Kann ich HEIC-Fotos vom iPhone umwandeln?"
    a: "Die meisten Browser können HEIC nicht direkt lesen. Wandeln Sie die Fotos zuerst mit dem HEIC-Konverter dieser Website in JPG um – ebenfalls offline im Browser – und fügen Sie dann die JPGs hier hinzu."
  - q: "Was bedeutet „Wie das Bild“?"
    a: "Die Seite erhält die Größe des Bildes bei 96 Pixeln pro Zoll, zuzüglich Rand. Das ist die beste Wahl für Screenshots und Zeichnungen, die nicht auf ein Papierformat skaliert werden sollen."
---

## So funktioniert es

### Vom Bild zur Seite

Für jedes Bild:

1. Es wird mit `createImageBitmap(file, { imageOrientation: 'from-image' })` dekodiert, damit die EXIF-Ausrichtung von Handyfotos berücksichtigt wird.
2. Es wird auf ein `<canvas>` gezeichnet, Ihre Drehung angewendet und neu kodiert: als **JPEG mit 92 % Qualität** für JPG-Fotos oder als **PNG** für PNG-, WebP- und GIF-Quellen, damit Transparenz und scharfe Kanten erhalten bleiben. Von GIFs wird das erste Bild verwendet.
3. Das Ergebnis wird mit **pdf-lib** (`embedJpg` / `embedPng`) ins PDF eingebettet.

### Seitenlayout

A4 misst 595 × 842 Punkt, US Letter 612 × 792 Punkt (1 Punkt = 1/72 Zoll). Das Bild wird so skaliert, dass es abzüglich des Rands auf jeder Seite in die Seite passt, mit gleichem Seitenverhältnis, und zentriert. Bei automatischer Ausrichtung wird die Seite quer gestellt, wenn das Bild breiter als hoch ist. Mit **Wie das Bild** hat eine Seite die Bildgröße bei 96 DPI – ein Screenshot mit 1920 × 1080 Pixeln ergibt eine Seite von 1440 × 810 Punkt – plus Rand.

### Bibliotheken

pdf-lib (MIT) wird erst beim Erstellen des PDFs von dieser Website geladen; das Vorschauraster nutzt die Bilddekodierung des Browsers. Von Servern Dritter wird nichts angefordert.

## Anwendungsfälle

- **Scans von Papierdokumenten verschicken** – Belege, Verträge, Hausaufgaben – als ein PDF, das jedes Büro öffnen kann.
- **Ausweise oder Gehaltsabrechnungen hochladen**, wenn ein Formular nur PDF akzeptiert, ohne sie vorher durch einen Online-Konverter zu schicken.
- **Ein Portfolio oder Fotoheft** aus JPGs in Ihrer Reihenfolge erstellen.
- **Screenshots archivieren** – einer Konfiguration, eines Fehlers oder einer Unterhaltung – als eine datierte Datei.
- **Druckfertige Seiten** in A4 oder Letter mit gleichmäßigen Rändern vorbereiten.
