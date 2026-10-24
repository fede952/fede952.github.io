---
title: "HEX to RGB & HSL Converter + Neon Palettes"
description: "Convert colours between HEX, RGB and HSL with a picker and one-click copy, and generate random cyberpunk neon palettes for UI, posters and themes. Free."
intro: "**NeonPalette** converts any colour between **HEX, RGB and HSL** as you pick or type it, and generates random three-colour **neon palettes**: cyan, magenta, electric blue, hot pink and friends, tuned for dark cyberpunk interfaces."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["hex to rgb", "rgb to hsl", "hex to hsl converter", "color converter", "neon color palette", "cyberpunk color palette", "color picker online", "neon colors hex"]
tags: ["design", "css", "colors", "tool"]
app_category: "DesignApplication"
tool_file: "/tools/neon-palette/"
tool_title: "NeonPalette colour converter and palette generator"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Pick a colour with the colour picker, or type a six-digit HEX code such as `#00E5FF` into the HEX field."
  - "The RGB and HSL fields and the preview bar update immediately."
  - "Press the copy button next to HEX, RGB or HSL to copy that notation, ready for CSS."
  - "Press **Generate Neon Palette** for three random neon colours from different hue families."
  - "Click any palette card to load that colour into the converter, then copy it in the format you need."
faq:
  - q: "How do I convert HEX to RGB?"
    a: "A HEX colour is three bytes written in hexadecimal: `#RRGGBB`. Convert each pair to decimal: `#00E5FF` is red 0x00 = 0, green 0xE5 = 229, blue 0xFF = 255, so `rgb(0, 229, 255)`. Three-digit shorthand like `#0EF` doubles each digit first (`#00EEFF`)."
  - q: "What is HSL and why use it?"
    a: "HSL describes a colour as hue (0–360° around the colour wheel), saturation (0–100% grey to vivid) and lightness (0% black to 100% white). It is easier to reason about than RGB: to make a lighter or more muted version of a colour you change one number instead of three."
  - q: "What makes a colour look neon?"
    a: "Very high saturation and medium lightness on a dark background. The generator keeps saturation between 85% and 100% and lightness between 45% and 60%, the band where colours look most luminous; lighter colours wash out towards pastel and darker ones lose their glow."
  - q: "Are neon colours accessible?"
    a: "On a dark background, cyan, green and yellow neons usually pass WCAG contrast for large text, while saturated blues, violets and magentas often do not. Use neon for accents, borders and headings, keep body text near-white, and check the contrast ratio of every text and background pair."
  - q: "Can I enter RGB or HSL values?"
    a: "The converter takes input from the picker and the HEX field; the RGB and HSL fields show the converted result for copying. To start from RGB, convert it to HEX or set it in the colour picker, which accepts RGB values in most browsers."
  - q: "Is anything stored or sent?"
    a: "No. All conversions are arithmetic in JavaScript inside this page, and palettes are generated with `Math.random()` locally."
---

## How it works

### Conversions

**HEX → RGB.** The six hex digits are parsed as one 24-bit integer, and the three channels are extracted with bit shifts: red = `(n >> 16) & 255`, green = `(n >> 8) & 255`, blue = `n & 255`.

**RGB → HSL.** Each channel is scaled to 0–1. With *max* and *min* the largest and smallest of the three:

- **Lightness** L = (max + min) / 2.
- **Saturation** S = 0 for greys; otherwise (max − min) / (max + min) when L ≤ 0.5, or (max − min) / (2 − max − min) when L > 0.5.
- **Hue** depends on which channel is largest: for red it is (G − B) / (max − min), for green 2 + (B − R) / (max − min), for blue 4 + (R − G) / (max − min), multiplied by 60° and wrapped into 0–360°.

Hue is rounded to whole degrees and S and L to whole percents, the precision CSS `hsl()` is normally written with.

| Colour | HEX | RGB | HSL |
|---|---|---|---|
| Neon cyan | `#00E5FF` | 0, 229, 255 | 186°, 100%, 50% |
| Hot magenta | `#FF2DCE` | 255, 45, 206 | 314°, 100%, 59% |
| Acid green | `#39FF14` | 57, 255, 20 | 111°, 100%, 54% |

### The neon generator

The generator knows eight hue families: cyan (170–195°), magenta (290–330°), electric blue (210–250°), neon green (100–150°), hot pink (330–355°), violet (260–290°), neon orange (15–40°) and neon yellow (50–70°). Each time you press the button it shuffles them, takes three, and for each picks a random hue inside the family's range, a saturation of 85–100% and a lightness of 45–60%. The HSL values are converted to HEX with the standard piecewise formula, so the three colours are always distinct families yet share the same vivid, glowing character.

## Use cases

- **CSS and design tokens.** Convert a brand HEX into `rgb()` for opacity tricks or `hsl()` for building lighter and darker variants.
- **Dark-mode and cyberpunk UIs.** Generate accent colours for buttons, borders, glows and charts on dark backgrounds.
- **Posters, thumbnails and stream overlays** with a synthwave or neon-sign look.
- **Game and app theming.** Pick three complementary neon accents for a HUD, a level or a terminal theme.
- **Learning colour models.** Watch how HEX, RGB and HSL describe the same colour, and how changing hue alone moves you around the wheel.
