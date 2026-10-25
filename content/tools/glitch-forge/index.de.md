---
title: "Glitch-Effekt für Fotos online"
description: "Glitch-Effekte für jedes Foto: RGB-Shift, Pixel Sorting, Scanlines und Rauschen, mit VHS- und Cyberpunk-Presets. PNG in voller Auflösung, ohne Upload."
intro: "**GlitchForge** macht aus einem Foto Glitch Art: chromatische RGB-Verschiebung, Pixel Sorting, CRT-Scanlines und digitales Rauschen, dosiert mit vier Reglern oder per Preset auf Knopfdruck. Das Bild wird auf einem Canvas in Ihrem Browser verarbeitet und als PNG in voller Auflösung exportiert."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["glitch effekt", "glitch art generator", "rgb split effekt", "pixel sorting online", "vhs effekt foto", "cyberpunk foto effekt", "chromatische aberration effekt", "glitch bild online"]
tags: ["bilder", "design", "kreativ", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/glitch-forge/"
tool_title: "GlitchForge Glitch-Art-Generator"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Ziehen Sie ein JPEG, PNG oder WebP auf die Canvas-Fläche oder klicken Sie, um eine Datei zu wählen."
  - "Probieren Sie zuerst ein Preset: **VHS**, **Cyberpunk**, **Corrupt** oder **Subtle**."
  - "Feinjustieren Sie mit den Reglern: **Amount** (Kontrast, Rauschen und Bildrisse), **RGB Shift**, **Scanlines** und **Pixel Sort**. Die Vorschau aktualisiert sich beim Ziehen."
  - "Mit **Download Cyberpunk Image** speichern Sie `glitchforge-export.png` in Originalauflösung."
  - "Mit **Reset Image** stellen Sie alle Regler auf null zurück und beginnen neu."
faq:
  - q: "Wird mein Foto irgendwohin hochgeladen?"
    a: "Nein. Das Bild wird auf ein HTML-Canvas gezeichnet, und jeder Effekt wird per JavaScript auf seinen Pixeln in Ihrem Browser berechnet. Nichts geht an einen Server – also unbedenklich auch für private Fotos."
  - q: "In welcher Auflösung wird heruntergeladen?"
    a: "In der Originalauflösung. Die Vorschau wird für den Bildschirm verkleinert, der Export zeichnet das Bild aber in voller Breite und Höhe neu, wendet dieselben Einstellungen an und speichert ein verlustfreies PNG."
  - q: "Warum sieht der Download etwas anders aus als die Vorschau?"
    a: "Rauschen und horizontale Bildrisse sind zufällig und werden für den Export in anderer Größe neu erzeugt. Der Charakter des Effekts bleibt gleich, einzelne Rauschpixel und Balkenpositionen ändern sich aber – wie auch bei jeder Reglerbewegung."
  - q: "Was ist Pixel Sorting?"
    a: "Ein Effekt, den Glitch-Künstler wie Kim Asendorf bekannt gemacht haben: Pixel eines Bereichs werden nach Helligkeit sortiert, helle Flächen verziehen sich zu Streifen. GlitchForge sortiert vertikale Abschnitte heller Pixel, sodass Lichter nach unten zerfließen, während dunkle Bereiche intakt bleiben."
  - q: "Was ist der RGB-Shift-Effekt?"
    a: "Er imitiert chromatische Aberration oder ein verschobenes Analogsignal: Der Rotkanal wird nach rechts, der Blaukanal nach links verschoben, an allen Kanten entstehen Farbsäume. Bei voller Stärke beträgt der Versatz 4 % der Bildbreite."
  - q: "Darf ich die Bilder kommerziell nutzen?"
    a: "Das Ergebnis ist Ihr eigenes Foto, von einem Algorithmus verändert; die Rechte entsprechen also denen des Originalbilds. Das Tool fügt kein Wasserzeichen hinzu und beansprucht nichts am Ergebnis."
---

## So funktioniert es

Beim Laden wird das Bild auf ein für die Vorschau skaliertes Canvas gezeichnet, und eine saubere Kopie seiner Pixel (`getImageData`) wird aufbewahrt. Bei jeder Reglerbewegung werden die Effekte auf eine frische Kopie dieser Pixel angewendet, in dieser Reihenfolge:

1. **Amount: Kontrast und Rauschen.** Jeder Farbkanal wird mit einem Kontrastfaktor bis 1,6× vom mittleren Grau weggeschoben, dann wird Zufallsrauschen von bis zu ±20 Stufen addiert und der Wert auf 0–255 begrenzt.
2. **RGB Shift.** Der Pixelpuffer wird kopiert; für jeden Pixel wird Rot von einem Pixel *shift* Spalten weiter links und Blau von *shift* Spalten weiter rechts gelesen, mit *shift* = RGB × 4 % der Breite. Grün bleibt, wo es ist – so entstehen rote und blaue Säume.
3. **Pixel Sort.** Jede zweite Spalte wird von oben nach unten durchlaufen. Wo die Luminanz (0,299 R + 0,587 G + 0,114 B, die Rec.-601-Gewichte) über der Schwelle 1 − Sort liegt, wird der Abschnitt heller Pixel – höchstens halbe Bildhöhe × Sort lang – gesammelt und von dunkel nach hell neu sortiert.
4. **Scanlines.** Ein Pixel hohe schwarze Linien alle 2–4 Pixel werden mit bis zu 50 % Deckkraft darübergelegt, wie auf einem Röhrenbildschirm.
5. **Bildrisse.** Liegt Amount über 25 %, werden bis zu acht zufällige dünne horizontale Streifen kopiert und seitlich versetzt – der klassische VHS-„Tracking“-Riss.

Die Presets sind nur Reglerstellungen:

| Preset | Amount | RGB | Scanlines | Sort |
|---|---|---|---|---|
| VHS | 45 | 60 | 70 | 10 |
| Cyberpunk | 65 | 80 | 40 | 35 |
| Corrupt | 85 | 50 | 20 | 90 |
| Subtle | 20 | 25 | 15 | 5 |

Das Rendern läuft über `requestAnimationFrame`, beim Ziehen eines Reglers wird also höchstens einmal pro Frame neu gezeichnet. Für den Download führt ein zweites Canvas in Originalgröße dieselbe Pipeline aus und speichert das Ergebnis mit `toDataURL('image/png')`.

## Anwendungsfälle

- **Albumcover, Poster und Thumbnails** im Synthwave-, VHS- oder Cyberpunk-Look, ohne schweren Editor.
- **Social-Media-Posts.** Ein geglitchtes Profilbild oder ein Story-Hintergrund fällt im Feed auf.
- **Assets für Spiele und Apps.** Erzeugen Sie Hintergründe mit „kaputtem“ Bildschirm, Fehlerbildschirme oder Texturen für „gehackte“ Oberflächen.
- **Gestalterisches Experimentieren.** Pixel Sorting und Kanalverschiebungen liefern schnell abstrakte Texturen aus gewöhnlichen Fotos.
- **Bildverarbeitung lehren.** Jeder Regler ist eine klassische Pixeloperation; schaltet man sie einzeln zu, sieht man, dass ein Bild nur eine Zahlenmatrix ist.
