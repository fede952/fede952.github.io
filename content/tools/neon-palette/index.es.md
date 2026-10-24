---
title: "Conversor HEX, RGB y HSL + Paletas Neón"
description: "Convierte colores entre HEX, RGB y HSL con selector y copia en un clic, y genera paletas neón cyberpunk aleatorias para interfaces, carteles y temas."
intro: "**NeonPalette** convierte cualquier color entre **HEX, RGB y HSL** mientras lo eliges o lo escribes, y genera **paletas neón** aleatorias de tres colores: cian, magenta, azul eléctrico, rosa intenso y compañía, pensadas para interfaces cyberpunk oscuras."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["convertir hex a rgb", "rgb a hsl", "conversor hex a hsl", "conversor de colores", "paleta de colores neón", "paleta cyberpunk", "selector de color online", "colores neón hex"]
tags: ["diseño", "css", "colores", "herramienta"]
app_category: "DesignApplication"
tool_file: "/tools/neon-palette/"
tool_title: "NeonPalette, conversor de colores y generador de paletas"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Elige un color con el selector, o escribe un código HEX de seis cifras como `#00E5FF` en el campo HEX."
  - "Los campos RGB y HSL y la barra de vista previa se actualizan al instante."
  - "Pulsa el botón de copiar junto a HEX, RGB o HSL para copiar esa notación, lista para CSS."
  - "Pulsa **Generar Paleta Neón** para obtener tres colores neón aleatorios de familias de tono distintas."
  - "Haz clic en cualquier tarjeta de la paleta para cargar ese color en el conversor y copiarlo en el formato que necesites."
faq:
  - q: "¿Cómo se convierte HEX a RGB?"
    a: "Un color HEX son tres bytes escritos en hexadecimal: `#RRGGBB`. Convierte cada par a decimal: `#00E5FF` es rojo 0x00 = 0, verde 0xE5 = 229, azul 0xFF = 255, es decir, `rgb(0, 229, 255)`. La forma abreviada de tres cifras como `#0EF` duplica antes cada cifra (`#00EEFF`)."
  - q: "¿Qué es HSL y por qué usarlo?"
    a: "HSL describe un color con tono (0–360° en la rueda de color), saturación (de 0 % gris a 100 % vivo) y luminosidad (de 0 % negro a 100 % blanco). Es más intuitivo que RGB: para obtener una versión más clara o más apagada de un color cambias un número en lugar de tres."
  - q: "¿Qué hace que un color parezca neón?"
    a: "Saturación muy alta y luminosidad media sobre fondo oscuro. El generador mantiene la saturación entre el 85 % y el 100 % y la luminosidad entre el 45 % y el 60 %, la franja en la que los colores parecen más luminosos; más claros tiran a pastel y más oscuros pierden el brillo."
  - q: "¿Los colores neón son accesibles?"
    a: "Sobre fondo oscuro, el cian, el verde y el amarillo neón suelen cumplir el contraste WCAG para texto grande, mientras que los azules, violetas y magentas saturados a menudo no. Usa el neón para acentos, bordes y títulos, deja el texto principal casi blanco y comprueba el contraste de cada par texto/fondo."
  - q: "¿Puedo introducir valores RGB o HSL?"
    a: "El conversor toma la entrada del selector y del campo HEX; los campos RGB y HSL muestran el resultado para copiarlo. Para partir de RGB, conviértelo a HEX o fíjalo en el selector de color, que en la mayoría de navegadores admite valores RGB."
  - q: "¿Se guarda o se envía algo?"
    a: "No. Todas las conversiones son aritmética en JavaScript dentro de esta página, y las paletas se generan localmente con `Math.random()`."
---

## Cómo funciona

### Conversiones

**HEX → RGB.** Las seis cifras hexadecimales se leen como un único entero de 24 bits y los tres canales se extraen con desplazamientos de bits: rojo = `(n >> 16) & 255`, verde = `(n >> 8) & 255`, azul = `n & 255`.

**RGB → HSL.** Cada canal se escala a 0–1. Con *max* y *min* el mayor y el menor de los tres:

- **Luminosidad** L = (max + min) / 2.
- **Saturación** S = 0 para los grises; si no, (max − min) / (max + min) cuando L ≤ 0,5, o (max − min) / (2 − max − min) cuando L > 0,5.
- **Tono**: depende de qué canal es el mayor: para el rojo es (G − B) / (max − min), para el verde 2 + (B − R) / (max − min) y para el azul 4 + (R − G) / (max − min), multiplicado por 60° y llevado al rango 0–360°.

El tono se redondea a grados enteros y S y L a porcentajes enteros, la precisión con la que se suele escribir `hsl()` en CSS.

| Color | HEX | RGB | HSL |
|---|---|---|---|
| Cian neón | `#00E5FF` | 0, 229, 255 | 186°, 100 %, 50 % |
| Magenta intenso | `#FF2DCE` | 255, 45, 206 | 314°, 100 %, 59 % |
| Verde ácido | `#39FF14` | 57, 255, 20 | 111°, 100 %, 54 % |

### El generador neón

El generador conoce ocho familias de tono: cian (170–195°), magenta (290–330°), azul eléctrico (210–250°), verde neón (100–150°), rosa intenso (330–355°), violeta (260–290°), naranja neón (15–40°) y amarillo neón (50–70°). Cada vez que pulsas el botón las baraja, toma tres y, para cada una, elige un tono aleatorio dentro de su rango, una saturación del 85–100 % y una luminosidad del 45–60 %. Los valores HSL se convierten a HEX con la fórmula por tramos estándar, así que los tres colores son siempre de familias distintas pero comparten el mismo carácter vivo y brillante.

## Casos de uso

- **CSS y design tokens.** Convierte un HEX de marca a `rgb()` para jugar con la opacidad o a `hsl()` para construir variantes más claras y oscuras.
- **Interfaces oscuras y cyberpunk.** Genera colores de acento para botones, bordes, brillos y gráficos sobre fondos oscuros.
- **Carteles, miniaturas y overlays de streaming** con estética synthwave o de letrero de neón.
- **Temas para juegos y apps.** Elige tres acentos neón complementarios para un HUD, un nivel o un tema de terminal.
- **Aprender modelos de color.** Observa cómo HEX, RGB y HSL describen el mismo color y cómo, cambiando solo el tono, recorres la rueda.
