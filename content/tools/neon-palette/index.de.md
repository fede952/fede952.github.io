---
title: "HEX-, RGB- & HSL-Umrechner + Neon-Paletten"
description: "Farben zwischen HEX, RGB und HSL umrechnen, mit Farbwähler und Kopieren per Klick, und zufällige Cyberpunk-Neon-Paletten für UIs und Poster erzeugen."
intro: "**NeonPalette** rechnet jede Farbe beim Auswählen oder Eintippen zwischen **HEX, RGB und HSL** um und erzeugt zufällige dreifarbige **Neon-Paletten** – Cyan, Magenta, Elektroblau, Pink und Co., abgestimmt auf dunkle Cyberpunk-Oberflächen."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["hex in rgb", "rgb in hsl", "hex in hsl umrechnen", "farbumrechner", "neon farbpalette", "cyberpunk farben", "farbwähler online", "neonfarben hex"]
tags: ["design", "css", "farben", "tool"]
app_category: "DesignApplication"
tool_file: "/tools/neon-palette/"
tool_title: "NeonPalette Farbumrechner und Palettengenerator"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Wählen Sie eine Farbe mit dem Farbwähler oder tippen Sie einen sechsstelligen HEX-Code wie `#00E5FF` in das HEX-Feld."
  - "Die Felder RGB und HSL und die Vorschauleiste aktualisieren sich sofort."
  - "Mit dem Kopierknopf neben HEX, RGB oder HSL kopieren Sie die jeweilige Schreibweise, bereit für CSS."
  - "Klicken Sie auf **Neon-Palette generieren** für drei zufällige Neonfarben aus verschiedenen Farbtonfamilien."
  - "Ein Klick auf eine Palettenkarte lädt die Farbe in den Umrechner, wo Sie sie im gewünschten Format kopieren."
faq:
  - q: "Wie rechnet man HEX in RGB um?"
    a: "Eine HEX-Farbe sind drei hexadezimal geschriebene Bytes: `#RRGGBB`. Jedes Paar wird ins Dezimalsystem umgerechnet: `#00E5FF` ist Rot 0x00 = 0, Grün 0xE5 = 229, Blau 0xFF = 255, also `rgb(0, 229, 255)`. Die dreistellige Kurzform wie `#0EF` verdoppelt zuerst jede Ziffer (`#00EEFF`)."
  - q: "Was ist HSL und wozu ist es gut?"
    a: "HSL beschreibt eine Farbe über Farbton (0–360° auf dem Farbkreis), Sättigung (0 % grau bis 100 % kräftig) und Helligkeit (0 % schwarz bis 100 % weiß). Das ist intuitiver als RGB: Für eine hellere oder gedecktere Variante ändern Sie eine Zahl statt drei."
  - q: "Was lässt eine Farbe neon wirken?"
    a: "Sehr hohe Sättigung und mittlere Helligkeit auf dunklem Grund. Der Generator hält die Sättigung zwischen 85 % und 100 % und die Helligkeit zwischen 45 % und 60 %, dem Bereich, in dem Farben am stärksten leuchten; hellere wirken pastellig, dunklere verlieren ihr Glühen."
  - q: "Sind Neonfarben barrierefrei?"
    a: "Auf dunklem Grund erreichen Cyan-, Grün- und Gelb-Neon meist den WCAG-Kontrast für große Schrift, gesättigte Blau-, Violett- und Magentatöne oft nicht. Nutzen Sie Neon für Akzente, Rahmen und Überschriften, halten Sie Fließtext nahezu weiß und prüfen Sie den Kontrast jeder Text-Hintergrund-Kombination."
  - q: "Kann ich RGB- oder HSL-Werte eingeben?"
    a: "Der Umrechner nimmt Eingaben aus dem Farbwähler und dem HEX-Feld; RGB und HSL zeigen das Ergebnis zum Kopieren. Wenn Sie von RGB ausgehen, rechnen Sie es in HEX um oder stellen Sie es im Farbwähler ein, der in den meisten Browsern RGB-Werte akzeptiert."
  - q: "Wird etwas gespeichert oder übertragen?"
    a: "Nein. Alle Umrechnungen sind Arithmetik in JavaScript innerhalb dieser Seite, und die Paletten entstehen lokal mit `Math.random()`."
---

## So funktioniert es

### Umrechnungen

**HEX → RGB.** Die sechs Hex-Ziffern werden als eine 24-Bit-Ganzzahl gelesen, die drei Kanäle per Bitverschiebung extrahiert: Rot = `(n >> 16) & 255`, Grün = `(n >> 8) & 255`, Blau = `n & 255`.

**RGB → HSL.** Jeder Kanal wird auf 0–1 skaliert. Mit *max* und *min* als größtem und kleinstem der drei Werte:

- **Helligkeit** L = (max + min) / 2.
- **Sättigung** S = 0 bei Grautönen; sonst (max − min) / (max + min) für L ≤ 0,5 bzw. (max − min) / (2 − max − min) für L > 0,5.
- **Farbton**: hängt davon ab, welcher Kanal am größten ist – für Rot (G − B) / (max − min), für Grün 2 + (B − R) / (max − min), für Blau 4 + (R − G) / (max − min), multipliziert mit 60° und in den Bereich 0–360° gebracht.

Der Farbton wird auf ganze Grad, S und L auf ganze Prozent gerundet – die übliche Genauigkeit von `hsl()` in CSS.

| Farbe | HEX | RGB | HSL |
|---|---|---|---|
| Neon-Cyan | `#00E5FF` | 0, 229, 255 | 186°, 100 %, 50 % |
| Knall-Magenta | `#FF2DCE` | 255, 45, 206 | 314°, 100 %, 59 % |
| Giftgrün | `#39FF14` | 57, 255, 20 | 111°, 100 %, 54 % |

### Der Neon-Generator

Der Generator kennt acht Farbtonfamilien: Cyan (170–195°), Magenta (290–330°), Elektroblau (210–250°), Neongrün (100–150°), Pink (330–355°), Violett (260–290°), Neonorange (15–40°) und Neongelb (50–70°). Bei jedem Klick mischt er sie, nimmt drei und wählt für jede einen zufälligen Farbton innerhalb ihres Bereichs, eine Sättigung von 85–100 % und eine Helligkeit von 45–60 %. Die HSL-Werte werden mit der üblichen stückweisen Formel in HEX umgerechnet; die drei Farben stammen so immer aus verschiedenen Familien, haben aber denselben kräftig leuchtenden Charakter.

## Anwendungsfälle

- **CSS und Design-Tokens.** Wandeln Sie ein Marken-HEX in `rgb()` für Transparenz-Tricks oder in `hsl()` für hellere und dunklere Varianten.
- **Dark-Mode- und Cyberpunk-UIs.** Erzeugen Sie Akzentfarben für Buttons, Rahmen, Glow-Effekte und Diagramme auf dunklem Grund.
- **Poster, Thumbnails und Stream-Overlays** im Synthwave- oder Leuchtreklame-Look.
- **Themes für Spiele und Apps.** Wählen Sie drei passende Neon-Akzente für ein HUD, ein Level oder ein Terminal-Theme.
- **Farbmodelle verstehen.** Sehen Sie, wie HEX, RGB und HSL dieselbe Farbe beschreiben und wie Sie sich nur mit dem Farbton um den Kreis bewegen.
