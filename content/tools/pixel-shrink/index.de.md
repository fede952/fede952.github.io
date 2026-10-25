---
title: "Bilder komprimieren online: JPG, PNG, WebP"
description: "Verkleinern Sie JPG-, PNG- und WebP-Bilder im Browser: Qualität, Zielgröße und Maximalbreite wählen, nach WebP konvertieren. Ohne Upload, ohne Anmeldung."
intro: "**PixelShrink** komprimiert und konvertiert Bilder auf Ihrem eigenen Gerät. Foto ablegen, Qualität, Zielgröße oder Maximalbreite wählen und ein kleineres JPG, PNG oder WebP herunterladen. Das Bild wird nie hochgeladen."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["bilder komprimieren", "bild verkleinern", "jpg komprimieren", "png komprimieren", "foto verkleinern ohne upload", "in webp umwandeln", "bildgröße reduzieren", "bildkompressor online"]
tags: ["bilder", "komprimierung", "datenschutz", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/pixel-shrink/"
tool_title: "PixelShrink Bildkompressor"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Ziehen Sie ein Bild in die Ablagefläche oder klicken Sie, um eine Datei zu wählen. PNG, JPEG, WebP und AVIF werden akzeptiert; die Vorschau zeigt Dateigröße und Abmessungen."
  - "Wählen Sie das **Ausgabeformat**: Original beibehalten oder in JPEG, PNG oder WebP umwandeln. Für Fotos ist WebP meist am kleinsten."
  - "Stellen Sie **Qualität** (1–100, Standard 75), eine **Maximalgröße** in MB und eine **Maximalbreite** in Pixeln ein. Die längere Seite wird proportional auf diesen Wert verkleinert."
  - "Klicken Sie auf **Bild komprimieren**. Die Vorher/Nachher-Ansicht zeigt beide Größen, beide Abmessungen und die Ersparnis in Prozent."
  - "Mit **Komprimiertes Bild herunterladen** speichern Sie das Ergebnis. Ist es nicht kleiner als das Original, weist das Tool darauf hin: Behalten Sie das Original oder probieren Sie ein anderes Format."
faq:
  - q: "Werden meine Bilder auf einen Server hochgeladen?"
    a: "Nein. Das Bild wird in Ihrem Browser in einem Web Worker im Hintergrund dekodiert, skaliert und neu kodiert. Es wird nichts übertragen: Nach dem Laden der Seite funktioniert das Tool auch offline. Darum eignet es sich auch für Screenshots von Dokumenten, Ausweisen und anderem Privaten."
  - q: "Welche Qualität sollte ich wählen?"
    a: "Für Fotos ist 70–80 der beste Kompromiss: Die Datei wird deutlich kleiner, Unterschiede sind in normaler Größe kaum zu sehen. Für Vorschaubilder reichen 50–60. Über 90 wächst die Datei schnell, ohne sichtbaren Gewinn."
  - q: "Sollte ich nach WebP konvertieren?"
    a: "Fürs Web meistens ja. WebP-Dateien sind bei ähnlicher Qualität typischerweise 25–35 % kleiner als JPEG, und alle aktuellen Browser zeigen sie an. Bleiben Sie bei JPEG, wenn das Bild an ein System geht, das nur JPG annimmt, etwa manche Upload-Formulare oder Druckdienste."
  - q: "Warum ist mein PNG größer geworden?"
    a: "PNG ist verlustfrei, daher ist ein als PNG gespeichertes Foto oft größer als das ursprüngliche JPEG. PixelShrink verkleinert PNGs, indem es die Farbpalette begrenzt – das klappt sehr gut bei Screenshots, Logos und flächigen Grafiken und schlecht bei Fotos. Für Fotos wählen Sie WebP oder JPEG."
  - q: "Kann ich ein Bild auf eine genaue Größe bringen, etwa unter 200 KB?"
    a: "Stellen Sie die **Maximalgröße** auf 0,2 MB. Ist die erste Kodierung größer, wiederholt die Bibliothek sie bis zu 10-mal und senkt dabei Qualität und Abmessungen jeweils ein wenig, bis die Datei passt. Bei sehr großen oder detailreichen Bildern hilft zusätzlich eine geringere Maximalbreite."
  - q: "Entfernt die Komprimierung EXIF-Daten und GPS-Standort?"
    a: "Ja. Das Bild wird auf ein Canvas neu gezeichnet und neu kodiert, ohne die Metadaten zu übernehmen. EXIF-Felder wie Kameramodell, Datum und GPS-Koordinaten fallen also weg. Wenn Sie nur Metadaten entfernen möchten, ohne neu zu komprimieren, nutzen Sie den EXIF Cleaner."
  - q: "Warum gibt es keine AVIF-Ausgabe?"
    a: "Die Ausgabe erzeugt der Bild-Encoder des Browsers selbst, und die meisten Browser können AVIF zwar anzeigen, aber nicht aus einem Canvas erzeugen. PixelShrink prüft das beim Laden und bietet AVIF nur an, wenn Ihr Browser es wirklich kodieren kann – statt heimlich ein PNG mit der Endung .avif zu liefern."
---

## So funktioniert es

PixelShrink ist eine schlanke Oberfläche für [browser-image-compression](https://github.com/Donaldcwl/browser-image-compression) (v2.0.2, auf dieser Website selbst gehostet). Sobald Sie auf Komprimieren klicken, übernimmt ein **Web Worker** die Arbeit, damit die Seite auch bei einem 20-Megapixel-Foto flüssig bleibt.

1. **Dekodieren.** Die Datei wird mit `createImageBitmap` (ersatzweise über ein `<img>`-Element) in eine Bitmap dekodiert, und die EXIF-Ausrichtung wird angewendet, damit Hochformatfotos nicht gedreht erscheinen.
2. **Skalieren.** Ist die längere Seite größer als die *Maximalbreite*, wird das Bild auf ein kleineres Canvas mit demselben Seitenverhältnis gezeichnet. Ein 6000 × 4000-Foto mit 2048-px-Grenze wird zu 2048 × 1365.
3. **Kodieren.** JPEG und WebP kodiert der Browser (`canvas.toBlob` / `OffscreenCanvas.convertToBlob`) mit Ihrer Qualitätseinstellung. PNG läuft über **UPNG.js**, das das Bild vor dem Schreiben eines verlustfreien PNG auf eine Palette von höchstens 4096 × Qualität Farben quantisiert (3.072 Farben beim Standard 75) – der Trick, mit dem Screenshots und UI-Grafiken oft um die Hälfte oder mehr schrumpfen.
4. **Zielgröße einhalten.** Ist das Ergebnis noch größer als die *Maximalgröße*, wird bis zu **10-mal** neu kodiert. Bei jedem Durchgang wird die Qualität mit 0,95 multipliziert (0,85 bei PNG) und die Abmessungen können um den Faktor 0,95 verkleinert werden, bis die Datei passt oder die Durchgänge aufgebraucht sind.

Die Vorher/Nachher-Ansicht vergleicht die Originaldatei mit dem Ergebnis, der Download ist eine lokale `blob:`-URL mit dem Namen `ihredatei-compressed.<format>`. Da das Bild aus den Pixeln neu kodiert wird, **werden Metadaten wie EXIF und GPS nicht übernommen**.

### Welches Format?

| Inhalt | Bestes Format | Warum |
|---|---|---|
| Fotos für Website oder Blog | WebP, Qualität 70–80 | Kleinste Dateien, von allen Browsern unterstützt |
| Fotos für E-Mail, Formulare, Druck | JPEG, Qualität 75–85 | Wird überall akzeptiert |
| Screenshots, Diagramme, Logos | PNG oder WebP | Scharfe Kanten und flächige Farben lassen sich gut komprimieren |
| Bilder mit Transparenz | PNG oder WebP | JPEG hat keinen Alphakanal |

**AVIF** erscheint nur, wenn der Browser es tatsächlich aus einem Canvas *kodieren* kann. Die meisten Browser können das derzeit nicht, und PixelShrink prüft das beim Laden, statt zu raten.

## Anwendungsfälle

- **Schnellere Webseiten.** Zu große Hero-Bilder sind die häufigste Ursache für einen schlechten Largest Contentful Paint. Ein 3-MB-JPEG als 2000-px-WebP mit Qualität 75 landet oft unter 300 KB.
- **Upload-Grenzen.** Behördenportale, Jobbörsen und Support-Tickets begrenzen Anhänge oft auf 1 oder 2 MB. Legen Sie die Maximalgröße fest und lassen Sie das Tool die passende Qualität finden.
- **E-Mail und Chat.** Schicken Sie fünf Urlaubsfotos statt einem, wenn jedes nur noch ein Zehntel so groß ist.
- **Private Dokumente.** Verkleinern Sie den Scan eines Ausweises oder Vertrags, ohne ihn einem unbekannten Online-Dienst zu überlassen.
- **App- und Spiel-Assets.** Wandeln Sie PNG-Sprites oder Screenshots in kleinere Dateien um, bevor sie in ein Repository wandern.
