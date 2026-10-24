---
title: "Text in einem Bild verstecken (LSB)"
description: "Verstecken Sie eine geheime Nachricht per LSB-Steganographie in einem Bild und lesen Sie sie wieder aus. Verlustfreier PNG-Export, alles lokal im Browser."
intro: "**Steganography Lab** versteckt eine Textnachricht in den Pixeln eines Bildes und liest sie später wieder aus. Das Bild sieht unverändert aus, denn jeder Farbwert ändert sich um höchstens 1 von 255. Alles passiert im Browser: Bild und Nachricht verlassen Ihr Gerät nie."
date: 2026-02-05
lastmod: 2026-10-24
reviewed: false
keywords: ["steganographie online", "text in bild verstecken", "lsb steganographie", "versteckte nachricht im bild", "nachricht aus bild auslesen", "png steganographie", "geheime nachricht bild", "steganographie tool"]
tags: ["datenschutz", "sicherheit", "bilder", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/steganography/"
tool_title: "Steganography Lab"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Ziehen Sie im Tab **Nachricht Verstecken** ein Bild in das Feld oder klicken Sie zur Auswahl (JPG, PNG, WebP oder GIF). Das Tool zeigt Größe und Kapazität in Bytes."
  - "Geben Sie Ihre Nachricht ein oder fügen Sie sie ein. Die Kapazitätsleiste füllt sich beim Tippen und wird nahe am Limit orange, dann rot."
  - "Klicken Sie auf **Kodieren und PNG Herunterladen**. Eine Datei `stego_<timestamp>.png` wird gespeichert, optisch identisch mit dem Original."
  - "Versenden Sie dieses PNG **als Datei** (E-Mail-Anhang, Cloud-Link, „als Dokument senden“), nicht als Foto, das eine Chat-App neu komprimiert."
  - "Zum Auslesen öffnen Sie den Tab **Nachricht Enthüllen**, laden das PNG und klicken auf **Versteckte Nachricht Dekodieren**. **Text Kopieren** übernimmt das Ergebnis."
faq:
  - q: "Ist die versteckte Nachricht verschlüsselt?"
    a: "Nein. Steganographie verbirgt, dass eine Nachricht existiert, schützt aber nicht ihren Inhalt. Wer das PNG in dieses Tool lädt oder das Schema kennt, kann sie lesen. Verschlüsseln Sie sensible Texte vorher (etwa mit age oder GPG) und verstecken Sie den Geheimtext."
  - q: "Warum muss die Ausgabe ein PNG sein?"
    a: "PNG ist verlustfrei: Jeder Pixelwert wird exakt gespeichert. JPEG und verlustbehaftetes WebP quantisieren die Farben beim Speichern neu und verwürfeln genau die niedrigsten Bits, in denen die Nachricht steckt. Deshalb akzeptiert der Auslese-Tab nur PNG-Dateien."
  - q: "Nach dem Versenden war die Nachricht weg. Warum?"
    a: "Die meisten Chat-Apps und sozialen Netzwerke skalieren und komprimieren Fotos neu, und ein Screenshot zeichnet die Pixel neu. Beides zerstört die versteckten Bits. Senden Sie das PNG als Datei oder Dokument, damit es Byte für Byte unverändert ankommt."
  - q: "Wie viel Text passt in ein Bild?"
    a: "Drei Bit pro vollständig deckendem Pixel, abzüglich 19 Byte für Kennung und Endmarke. Ein Foto mit 1920×1080 Pixeln fasst etwa 777.000 Byte. Gezählt wird in UTF-8-Bytes: Umlaute belegen zwei, viele Emojis vier."
  - q: "Können Steganalyse-Tools das erkennen?"
    a: "Ja. Sequenzielles LSB-Einbetten ist genau der Lehrbuchfall, den statistische Tests wie Chi-Quadrat oder die RS-Analyse aufspüren – besonders bei hoher Auslastung. Nutzen Sie das Tool zum Lernen und für einfache Privatsphäre, nicht für verdeckte Kommunikation gegen fähige Gegner."
  - q: "Funktioniert es mit transparenten PNGs?"
    a: "Ja. Nur vollständig deckende Pixel tragen Daten, weil Browser halbtransparente Pixel vormultipliziert speichern und deren niedrige Bits nicht erhalten blieben. Transparente Bereiche bleiben unverändert und verringern lediglich die Kapazität."
  - q: "Wird mein Bild irgendwo hochgeladen?"
    a: "Nein. Die Datei wird mit der FileReader-API gelesen und auf einem Canvas im Browser-Tab verarbeitet. Es gibt keinen Server: Sie können die Seite laden, offline gehen, und es funktioniert weiter."
---

## So funktioniert es

Die Technik heißt **Substitution des niederwertigsten Bits (LSB)** und ist die klassische Form der Bild-Steganographie (ausführlicher im [Leitfaden Steganographie 101](/de/learn/guides/steganography-101-hidden-messages/)).

**1. Nutzlast bauen.** Ihr Text wird als UTF-8 kodiert und so eingerahmt:

```
STEGO_V1::<Ihre Nachricht>\0\0\0END\0\0\0
```

Das Präfix `STEGO_V1::` lässt den Decoder sofort erkennen, ob ein Bild eine Nachricht trägt; die von Nullbytes umgebene Marke `END` zeigt, wo sie endet.

**2. Pixel lesen.** Das Bild wird in Originalgröße und ohne Glättung auf ein HTML-Canvas gezeichnet; `getImageData()` liefert jedes Pixel als Rot-, Grün-, Blau- und Alpha-Byte.

**3. Ein Bit pro Farbkanal.** Die Bits der Nutzlast werden, höchstwertiges zuerst, nacheinander in das niedrigste Bit der R-, G- und B-Bytes jedes vollständig deckenden Pixels geschrieben, in Leserichtung ab oben links. Jedes Byte wird zu `(Wert & 0xFE) | Bit` – ein Kanal ändert sich um 0 oder 1, der Unterschied ist unsichtbar. Alpha wird nie verändert, und nicht vollständig deckende Pixel werden übersprungen, weil das Canvas ihre Farben vormultipliziert und die niedrigen Bits verloren gingen.

**4. Verlustfrei exportieren.** Das veränderte Canvas wird mit `toBlob('image/png')` gespeichert. Nebeneffekt: Die Ausgabe enthält **keine EXIF-Metadaten** (Kamera, GPS, Datum), denn das Canvas kennt nur Pixel.

**5. Dekodieren.** Der Auslese-Tab macht das Gegenteil: Er sammelt die niedrigen Bits derselben Kanäle, setzt Bytes zusammen und vergleicht die ersten zehn mit `STEGO_V1::`. Passen sie nicht, bricht er sofort ab – ein großes, sauberes Foto wird also fast augenblicklich abgelehnt. Andernfalls liest er bis zur Endmarke und wandelt die Bytes wieder in Text um.

| Bild | Deckende Pixel | Kapazität |
|---|---|---|
| 800×600 | 480.000 | ≈ 179.981 Byte |
| 1920×1080 | 2.073.600 | ≈ 777.581 Byte |
| 4000×3000 | 12.000.000 | ≈ 4,5 MB |

Je mehr Kapazität Sie nutzen, desto leichter fällt das Bild bei statistischer Steganalyse auf. Eine kurze Nachricht in einem großen, verrauschten Foto ist viel schwerer zu entdecken als eine lange in einer Grafik mit Flächenfarben.

## Anwendungsfälle

- **Lernen und Lehren.** Sehen Sie genau, was LSB-Einbettung bewirkt, und versuchen Sie dann, sie zu brechen: Komprimieren Sie das PNG als JPEG und sehen Sie zu, wie die Nachricht verschwindet.
- **CTF-Training.** Steganographie-Aufgaben verstecken Flags oft in den LSBs; eigene Beispiele machen das Muster in Tools wie `zsteg` oder StegSolve leicht erkennbar.
- **Eigene Bilder markieren.** Betten Sie einen Vermerk (Urheber, Datum) in ein PNG ein, das Sie als Datei teilen. Bearbeitung übersteht er nicht, aber er belegt, dass eine Kopie unverändert ist.
- **Ein spielerisches Geheimnis.** Verstecken Sie eine Nachricht in einem Urlaubsfoto für jemanden, der weiß, wo er suchen muss.
- **Bereits verschlüsselten Text transportieren.** Fügen Sie Geheimtext ein (zum Beispiel ASCII-armored GPG-Ausgabe) und kombinieren Sie Vertraulichkeit mit Unauffälligkeit.

Für die umgekehrte Aufgabe – Daten entfernen, die in den Metadaten eines Fotos statt in seinen Pixeln stecken – nutzen Sie den [EXIF Cleaner](/de/tools/exif-cleaner/).
