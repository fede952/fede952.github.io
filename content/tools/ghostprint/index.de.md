---
title: "Browser-Fingerprint-Test: Wie einzigartig?"
description: "Sehen Sie den Fingerprint, den Ihr Browser jeder Website liefert (Canvas, WebGL-GPU, Audio, Schriften, Bildschirm, Zeitzone), plus geschätzten Score."
intro: "**GhostPrint** liest dieselben Signale, die Tracking- und Betrugserkennungs-Skripte auf den meisten Websites unbemerkt auslesen, zeigt sie Ihnen einzeln und schätzt, wie gut sie Ihren Browser identifizierbar machen. Jede Messung läuft in dieser Seite; es wird nichts übertragen."
date: 2026-07-06
lastmod: 2026-10-24
reviewed: false
keywords: ["browser fingerprint test", "browser fingerprinting", "digitaler fingerabdruck browser", "canvas fingerprint", "webgl fingerprint", "wie verfolgbar bin ich", "bin ich einzigartig", "tracking ohne cookies"]
tags: ["datenschutz", "sicherheit", "fingerprinting", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/ghostprint/"
tool_title: "GhostPrint Browser-Fingerprint-Test"
tool_height: 2200
tool_settle_ms: 3000
tool_sandbox: "allow-scripts allow-same-origin allow-downloads allow-modals"
tool_allow: "clipboard-write"
howto:
  - "Öffnen Sie die Seite: Der Scan startet von selbst. GhostPrint prüft in etwa zwei Sekunden 12 Signale und listet jedes auf, sobald es gelesen ist; **Re-scan** wiederholt ihn."
  - "Lesen Sie Urteil und Hauptzahl, etwa „1 in 2.1 million“: die geschätzte Zahl an Browsern, die man durchsehen müsste, bis einer denselben Fingerprint hat."
  - "Gehen Sie die Signalkarten durch. Jede zeigt den Rohwert, die Bits an identifizierender Information, die sie beiträgt, und eine Erklärung in einer Zeile."
  - "Merken Sie sich Ihre **Fingerprint ID**. Öffnen Sie die Seite im privaten Fenster oder nach dem Löschen der Cookies: Die ID bleibt gleich – genau das ist der Sinn von Fingerprinting."
  - "Mit **Download shareable card** oder **Copy summary** vergleichen Sie Browser oder zeigen einem Kollegen, warum Cookies löschen nicht reicht."
faq:
  - q: "Was ist Browser-Fingerprinting?"
    a: "Eine Methode, einen Browser wiederzuerkennen, ohne etwas auf ihm zu speichern. Ein Skript liest Dutzende kleiner Eigenschaften (Bildschirmgröße, installierte Schriften, GPU-Modell, wie Ihr Gerät ein verstecktes Bild zeichnet) und kombiniert sie zu einer Kennung. Ohne Cookie – deshalb überlebt die Kennung privates Surfen, das Löschen von Cookies und die meisten „Daten löschen“-Schaltflächen."
  - q: "Ist der Einzigartigkeits-Score eine Messung?"
    a: "Er ist eine Schätzung. Jedes Signal erhält ein festes Gewicht in Bit, je nachdem, wie viel identifizierende Information diese Art von Signal laut veröffentlichter Fingerprinting-Forschung typischerweise trägt. Die Gewichte werden addiert, wegen der Korrelation der Signale um 18 % abgewertet und auf etwa 5,5 Milliarden begrenzt, die Zahl der Internetnutzer. GhostPrint vergleicht Sie nicht mit einer Datenbank anderer Besucher – darum kommt es ohne Datensammlung aus."
  - q: "Verhindert der Inkognito- oder Privatmodus Fingerprinting?"
    a: "Nein. Der Privatmodus löscht beim Schließen Cookies und Verlauf, aber GPU, Schriften, Bildschirm und Canvas-Rendering bleiben gleich – also auch der Fingerprint. Testen Sie es: Die hier angezeigte Fingerprint ID ändert sich im privaten Fenster nicht."
  - q: "Welche Browser schützen am besten vor Fingerprinting?"
    a: "Tor Browser lässt alle Nutzer gleich aussehen, der wirksamste Ansatz. Brave randomisiert Canvas-, WebGL- und Audio-Werte pro Website. Firefox bietet `privacy.resistFingerprinting`, das viele Werte vereinheitlicht. Safari reduziert einige Signale standardmäßig. Chrome und Edge geben die meisten preis, sofern Sie keine Erweiterung installieren."
  - q: "Helfen Anti-Fingerprinting-Erweiterungen?"
    a: "Manche ja, vor allem solche, die Canvas und Audio randomisieren – doch eine seltene Erweiterung kann selbst zum Unterscheidungsmerkmal werden. Auch das komplette Blockieren eines Signals wie WebGL kann Sie auffälliger machen. Ziel ist, gewöhnlich auszusehen, nicht unsichtbar."
  - q: "Werden meine Daten an Ihren Server gesendet?"
    a: "Nein. Alle Messungen laufen als JavaScript in dieser Seite, das Ergebnis wird lokal angezeigt. Das Tool stellt keine Anfragen an Analyse- oder Fingerprinting-Dienste, und die herunterladbare Karte entsteht auf einem Canvas in Ihrem Browser."
---

## So funktioniert es

GhostPrint erfasst zwölf Signale. Fünf werden aktiv *gemessen*, indem etwas gezeichnet oder berechnet wird; die übrigen werden über Standard-Browser-APIs gelesen.

**Rendering-Signale**

- **Canvas.** Die Seite zeichnet Text (mit Emoji und Akzentbuchstaben), ein gefülltes Rechteck und einen Bogen auf ein verstecktes 240 × 60-Canvas, exportiert es mit `toDataURL()` und bildet einen 32-Bit-FNV-1a-Hash. Schriften, Kantenglättung, GPU und Grafiktreiber hinterlassen winzige Pixelunterschiede, daher unterscheidet sich der Hash von Gerät zu Gerät. Eine leere oder winzige Ausgabe gilt als blockiert.
- **WebGL.** Es öffnet einen WebGL-Kontext, liest über `WEBGL_debug_renderer_info` den unmaskierten GPU-Hersteller und -Renderer und hasht sie zusammen mit WebGL-Version, Shading-Language-Version, maximaler Textur- und Renderbuffer-Größe, Vertex-Attribut-Limit und der vollständigen Liste unterstützter Erweiterungen.
- **Audio.** Ein `OfflineAudioContext` berechnet eine Sekunde einer 10-kHz-Dreieckswelle durch einen Dynamikkompressor. Die Summe von 1.000 Ausgabewerten wird gehasht; Gleitkomma-Unterschiede der Audio-Stacks lassen sie je nach Gerät variieren. Nach 900 ms gibt die Messung auf.
- **Schriften.** Ein versteckter 72-px-Teststring wird in den drei generischen Familien (serif, sans-serif, monospace) gemessen und dann erneut mit jeder von **53 verbreiteten Schriften** an erster Stelle. Ändern sich Breite oder Höhe, ist die Schrift installiert. Ihr Schriftbestand spiegelt Betriebssystem, dessen Sprache und installierte Software wider.

**Nur gelesene Signale:** User-Agent-String, Plattform, Bildschirmauflösung mit Pixelverhältnis und Farbtiefe, Zeitzone mit UTC-Versatz, bevorzugte Sprachen, CPU-Kerne, Gerätespeicher und Touch-Punkte, Farbschema- und Bewegungsreduktions-Präferenz sowie der Status von Cookies, Do-Not-Track und Global Privacy Control.

### Von Signalen zu „1 von N“

Jedes Signal hat ein festes Gewicht in Bit:

| Signal | Bit |
|---|---|
| Canvas-Fingerprint | 8 |
| Schriften | 0,45 pro erkannter Schrift, max. 8 |
| GPU-Modell (WebGL) | 7 |
| User Agent | 6 (8 bei ungewöhnlicher Länge) |
| Audio-Fingerprint | 5 |
| Bildschirm, Zeitzone | je 2 |
| Sprachen, Hardware | je 1,5 |
| Plattform | 1 |
| Anzeigepräferenzen, Datenschutz-Flags | je 0,5 |

Ein blockiertes oder randomisiertes Signal zählt 0 Bit. Die Summe wird mit **0,82** multipliziert, um Korrelationen zu berücksichtigen (eine bestimmte GPU impliziert meist eine bestimmte Plattform), und dann in „1 von 2^Bit“ umgerechnet, gedeckelt bei 5,5 Milliarden. Die Urteilsstufen lauten *Blending in* unter 10 Bit, *Identifiable* ab 10, *Highly unique* ab 18 und *Ghost-level exposure* ab 28.

Die **Fingerprint ID** besteht aus drei vierstelligen FNV-1a-Hashes: von User Agent, Plattform und Bildschirm; von den WebGL- und Canvas-Hashes; und von allen Signalen zusammen. Dass sie im privaten Fenster gleich bleibt, ist die praktische Demonstration.

## Anwendungsfälle

- **Verstehen, warum „Cookies löschen“ kein Datenschutz ist.** Test ausführen, alles löschen, erneut ausführen: gleiche ID.
- **Browser und Einstellungen vergleichen.** Probieren Sie Firefox mit `resistFingerprinting`, Brave, Tor Browser und Ihren Alltagsbrowser, und beobachten Sie, welche Karten auf 0 Bit fallen.
- **Sicherheitsschulungen.** Eine 30-Sekunden-Demo der GPU- und Schriftkarten macht das Konzept auch für nicht-technische Kollegen greifbar.
- **Annahmen zur Betrugserkennung prüfen.** Wer Risikobewertungen entwickelt, sieht, welche Signale stabil sind und welche sich leicht blockieren lassen.
- **Ergebnis teilen.** Die herunterladbare Karte im Format 1200 × 630 (Social-Preview-Größe) zeigt Urteil, Entropie und ID, ohne die Rohwerte offenzulegen.
