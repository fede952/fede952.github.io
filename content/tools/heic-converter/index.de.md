---
title: "HEIC in JPG umwandeln, ohne Upload"
description: "iPhone-HEIC-Fotos im Browser in JPG oder PNG umwandeln: im Stapel, mit einstellbarer Qualität, optionalem Entfernen von EXIF/GPS und ZIP-Download."
intro: "Wandeln Sie **iPhone-HEIC-Fotos in JPG oder PNG** um, ohne sie irgendwo hochzuladen: Legen Sie eine oder hundert Dateien ab, wählen Sie Format und Qualität, entscheiden Sie, ob EXIF-Metadaten und GPS-Standort entfernt werden, und laden Sie jede Datei einzeln oder ein ZIP herunter. Der Decoder läuft in diesem Browser-Tab."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["heic in jpg umwandeln", "heic in jpg", "heic konverter", "heic in png", "iphone foto in jpg", "heic datei öffnen", "heic online umwandeln", "heic jpg kostenlos"]
tags: ["bilder", "datenschutz", "konverter", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/heic-converter/"
tool_title: "HEIC-zu-JPG- und PNG-Konverter"
tool_height: 720
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Ziehen Sie Ihre `.heic`- oder `.heif`-Fotos in das Feld oder klicken Sie, um sie auszuwählen. Mehrere auf einmal sind möglich, weitere können später folgen."
  - "Beim ersten Mal lädt die Seite ihren HEIC-Decoder (ca. 1,5 MB, einmal pro Besuch). Danach wird jedes Foto nacheinander dekodiert und umgewandelt; neben dem Namen erscheinen ein Vorschaubild und die neue Größe."
  - "Wählen Sie **JPG** (kleinere Dateien, einstellbare **JPG-Qualität**) oder **PNG** (verlustfrei, größer). Wenn Sie eine Option ändern, werden die Fotos in der Liste neu umgewandelt."
  - "Lassen Sie **Metadaten entfernen (EXIF, GPS-Standort)** aktiviert, um saubere Dateien zu erhalten, oder deaktivieren Sie es, um Kameradaten und Standort im JPG zu behalten."
  - "Klicken Sie bei einem Foto auf **Herunterladen** oder auf **Alle herunterladen (.zip)**, um alle umgewandelten Dateien in einem Archiv zu speichern."
faq:
  - q: "Werden meine Fotos auf einen Server hochgeladen?"
    a: "Nein. Die Dateien werden mit der File-API des Browsers gelesen und von einer WebAssembly-Version von libheif dekodiert, die in diesem Tab läuft. Netzwerkanfragen gibt es nur für den Decoder selbst; Ihre Fotos verlassen das Gerät nie. Sie können das im Netzwerk-Panel des Browsers während der Umwandlung prüfen."
  - q: "Warum speichert das iPhone Fotos als HEIC?"
    a: "HEIC speichert ein mit HEVC (H.265) komprimiertes Bild in einem HEIF-Container. Bei ähnlicher Qualität sind die Dateien etwa halb so groß wie JPEG, deshalb nutzt iOS das Format standardmäßig. Viele Windows-Programme, Websites und ältere Geräte können es aber nicht öffnen – daher die Umwandlung."
  - q: "Verliere ich Qualität?"
    a: "Die Umwandlung in JPEG komprimiert das Bild erneut. Bei der Standardqualität 85 ist der Unterschied kaum zu sehen, und die Datei bleibt klein; wählen Sie 95–100, wenn Sie das Foto bearbeiten möchten. PNG ist verlustfrei, aber oft drei- bis fünfmal so groß wie das HEIC-Original."
  - q: "Was entfernt „Metadaten entfernen“?"
    a: "Alles außer den Pixeln: EXIF-Kameradaten, Datum und Uhrzeit und vor allem die GPS-Position, die verraten kann, wo Sie wohnen oder arbeiten. Ist die Option aus, kopiert der Konverter den ursprünglichen EXIF-Block ins JPEG und setzt das Orientierungs-Tag zurück, weil der Decoder das Bild bereits gedreht hat."
  - q: "Mein HEIC enthält mehrere Bilder (Live Photo, Serie). Welches wird umgewandelt?"
    a: "Das Hauptbild, also das, das die Fotos-App anzeigt. Der bewegte Teil eines Live Photos ist eine separate Videodatei und wird nicht übernommen."
  - q: "Gibt es eine Größen- oder Mengenbegrenzung?"
    a: "Nur den Arbeitsspeicher Ihres Geräts. Jedes Foto wird in Rohpixel dekodiert (ein 12-Megapixel-Foto braucht während der Umwandlung etwa 48 MB), sehr große Stapel gehen auf einem Computer also schneller als auf einem älteren Handy."
  - q: "Kann ich HEIC in PNG mit Transparenz umwandeln?"
    a: "Fotos aus Handykameras haben keine Transparenz. Hat ein HEIF-Bild einen Alphakanal, bleibt er im PNG erhalten; JPEG kennt keine Transparenz und füllt sie schwarz."
---

## So funktioniert es

### Dekodieren ohne Server

Browser außer Safari können HEIC nicht selbst öffnen, denn das Format verpackt **HEVC**-komprimierte Bilder in einem **HEIF**-Container (ISO/IEC 23008-12). Diese Seite bringt **libheif** mit – die Open-Source-Referenzbibliothek für HEIF, vom Projekt libheif-js nach WebAssembly kompiliert – und lädt sie erst, wenn Sie die erste Datei ablegen. So bleibt die Seite selbst schlank.

Für jede Datei:

1. Die Bytes werden mit der File-API gelesen, und die `ftyp`-Box wird auf eine HEIF-Marke geprüft (`heic`, `heix`, `mif1` …). Ein umbenanntes JPEG wird gemeldet, statt den Decoder abstürzen zu lassen.
2. libheif dekodiert das Hauptbild in eine RGBA-Bitmap. In der Datei gespeicherte Drehung und Spiegelung (`irot`, `imir`) werden dabei angewendet.
3. Die Bitmap wird auf ein `<canvas>` gezeichnet und mit `canvas.toBlob()` als JPEG in der gewählten Qualität oder als PNG kodiert.

### Metadaten

Ein Canvas trägt nie Metadaten, eine umgewandelte Datei ist also standardmäßig sauber. Wenn Sie die Metadaten behalten möchten, analysiert der Konverter den HEIF-Container selbst – die `meta`-Box, die Elementliste (`iinf`) und die Elementpositionen (`iloc`) –, sucht das Element vom Typ `Exif` und fügt es als normales **APP1**-Segment ins JPEG ein. In der Kopie wird das Tag `Orientation` auf 1 (normal) gesetzt, sonst würden Bildbetrachter ein bereits aufrechtes Foto erneut drehen. PNG-Ausgaben sind immer ohne Metadaten.

### ZIP-Download

Bei mehr als einer Datei lädt **Alle herunterladen** eine kleine ZIP-Bibliothek (JSZip), fügt alle umgewandelten Dateien hinzu und speichert ein einziges Archiv. Doppelte Namen erhalten ein Zahlensuffix (`IMG_0001-2.jpg`).

## Anwendungsfälle

- **iPhone-Fotos an Windows-Nutzer oder Formulare schicken**, die nur JPG oder PNG annehmen: Bewerbungen, Versicherungsfälle, Behördenportale.
- **Im Web veröffentlichen, ohne den Standort preiszugeben.** Umwandeln und EXIF entfernen in einem Schritt, bevor Sie auf einen Marktplatz oder in ein Forum hochladen.
- **Archivieren.** Einen Ordner mit Urlaubsfotos für den alten Laptop eines Familienmitglieds oder einen digitalen Bilderrahmen in JPG umwandeln.
- **Designer und Entwickler**, die HEIC-Screenshots oder Mockups erhalten und PNG für die Dokumentation brauchen.
- **Sensible Bilder** – Dokumente, Ausweise, medizinische Fotos –, die nicht durch einen Online-Konverter laufen sollten, den Sie nicht prüfen können.
