---
title: "Contador de Palabras y Mayúsculas"
description: "Cuenta palabras, caracteres, líneas y tiempo de lectura en vivo; cambia mayúsculas, quita líneas duplicadas, limpia espacios o pasa el texto a leetspeak."
intro: "**StringMaster** es un pequeño banco de trabajo para texto. Pega cualquier cosa y cuenta palabras, caracteres, líneas y tiempo de lectura mientras escribes; con un clic cambia mayúsculas y minúsculas, quita líneas duplicadas, limpia espacios o convierte el texto en leetspeak. El texto se queda en la pestaña de tu navegador."
date: 2026-02-10
lastmod: 2026-10-24
reviewed: false
keywords: ["contador de palabras", "contador de caracteres", "herramientas de texto online", "convertir mayúsculas minúsculas", "eliminar líneas duplicadas", "quitar espacios online", "convertidor leetspeak", "tiempo de lectura"]
tags: ["texto", "herramientas-dev", "escritura", "herramienta"]
app_category: "UtilitiesApplication"
tool_file: "/tools/string-master/"
tool_title: "StringMaster, herramientas de texto"
tool_height: 750
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Pega o escribe tu texto en el cuadro **Entrada**. **Palabras**, **Caracteres**, **Líneas** y **Tiempo Lectura** se actualizan con cada tecla."
  - "Pulsa **Mayúsculas** o **Minúsculas** para convertir todo el texto."
  - "Pulsa **Quitar Duplicados** para conservar solo la primera aparición de cada línea, o **Recortar Espacios** para quitar espacios en los extremos de las líneas y compactar las líneas vacías."
  - "Pulsa **Modo Hacker** para reescribir el texto en leetspeak (`hello` → `h3110`)."
  - "Pulsa **Copiar** para llevar el resultado al portapapeles. Las transformaciones sustituyen el texto, así que copia antes el original si puedes necesitarlo."
faq:
  - q: "¿Cómo se cuentan las palabras?"
    a: "El texto se divide por cualquier secuencia de espacios en blanco (espacios, tabuladores, saltos de línea): `físico-químico` es una palabra y `p. ej. esto` son tres. Los idiomas que se escriben sin espacios, como el chino o el japonés, cuentan una palabra por bloque, así que para ellos usa el recuento de caracteres."
  - q: "¿Los emoji y las letras con tilde cuentan como un carácter?"
    a: "Sí. El contador usa el segmentador de grafemas del navegador (`Intl.Segmenter`), así que 👍, ñ e incluso un emoji de \"familia\" formado por varios code points cuentan una vez, tal como los ves. Algunas plataformas, como los SMS, cuentan de otra forma (en unidades UTF-16 o bytes) y llegan antes al límite."
  - q: "¿Cómo se estima el tiempo de lectura?"
    a: "Número de palabras dividido entre 200 palabras por minuto, una media habitual para leer en pantalla, redondeado hacia arriba. Por debajo de un minuto muestra segundos (`45s`) y por encima minutos enteros (`4m`). Un texto técnico o denso suele leerse más despacio."
  - q: "¿Quitar Duplicados distingue mayúsculas?"
    a: "Sí, y es exacto: `Manzana`, `manzana` y `manzana ` (con espacio final) son tres líneas distintas. Aplica antes **Recortar Espacios** y **Minúsculas** si quieres una comparación más flexible. Se conserva el orden de las primeras apariciones, y las líneas vacías repetidas también se reducen a una."
  - q: "¿Puedo deshacer una transformación?"
    a: "No hay botón de deshacer y, como el texto se sustituye por script, Ctrl+Z no siempre lo recupera en todos los navegadores. Minúsculas, Quitar Duplicados, Recortar Espacios y Modo Hacker pierden información, así que guarda una copia del original."
  - q: "¿Se puede volver atrás desde el leetspeak?"
    a: "No de forma fiable. Tanto `i` como `l` se convierten en `1`, y los dígitos que ya había en el texto no se distinguen de las letras sustituidas. El Modo Hacker es un efecto de estilo de un solo sentido, no una codificación."
  - q: "¿Se envía mi texto a algún sitio?"
    a: "No. Los recuentos y transformaciones son JavaScript simple dentro de la página; no se guarda ni se transmite nada. Puedes usarlo con borradores, logs o documentos internos."
---

## Cómo funciona

Cada pulsación en el cuadro ejecuta el mismo pequeño análisis:

- **Palabras** = número de bloques no vacíos tras dividir el texto (sin espacios en los extremos) por espacios en blanco (`/\s+/`).
- **Caracteres** = número de clústeres de grafemas, los caracteres que contaría una persona, mediante `Intl.Segmenter`; los navegadores sin soporte cuentan code points Unicode. Los espacios y saltos de línea cuentan como caracteres.
- **Líneas** = número de líneas separadas por saltos de línea. Un cuadro vacío muestra 0, y un salto final añade una última línea vacía.
- **Tiempo Lectura** = ⌈palabras ÷ 200 × 60⌉ segundos, en segundos por debajo de un minuto y en minutos redondeados hacia arriba por encima.

Cada botón aplica una transformación a todo el texto y vuelve a contar:

| Botón | Qué hace | Ejemplo |
|---|---|---|
| **Mayúsculas** | Mayúsculas Unicode (`toUpperCase`) | `straße` → `STRASSE` |
| **Minúsculas** | Minúsculas Unicode (`toLowerCase`) | `HoLA` → `hola` |
| **Quitar Duplicados** | Conserva la primera copia de cada línea idéntica, en orden | `a, b, a, c` → `a, b, c` |
| **Recortar Espacios** | Recorta cada línea, permite como mucho una línea vacía seguida y recorta los extremos | `··texto··` → `texto` |
| **Modo Hacker** | Sustituye a→4, b→8, e→3, g→9, i→1, l→1, o→0, s→5, t→7 | `get root` → `937 r007` |
| **Copiar** | Copia el texto con la Clipboard API | — |

Dos detalles útiles. La conversión de mayúsculas no depende del idioma, así que la *i* turca con y sin punto sigue las reglas Unicode genéricas. Recortar Espacios solo actúa sobre los extremos de línea y las líneas vacías: los espacios dobles *dentro* de una línea se mantienen, de modo que la sangría del código y las tablas siguen legibles.

## Casos de uso

- **Escribir con un límite.** Comprueba redacciones, meta descriptions, resúmenes o publicaciones sociales frente a un máximo de palabras o caracteres mientras editas.
- **Limpiar listas.** Pega una columna de correos, hostnames o IDs exportada de una hoja de cálculo y quita los duplicados con un clic; pasa antes a minúsculas datos como las direcciones de correo.
- **Ordenar logs y salidas pegadas.** Elimina espacios finales y compacta las líneas vacías de la salida del terminal antes de pegarla en un ticket o documento.
- **Normalizar identificadores.** Pon en minúsculas etiquetas o claves antes de compararlas, o en mayúsculas constantes y palabras clave SQL.
- **Texto divertido.** Convierte un nombre de usuario, un banner o el nombre de tu equipo de CTF en leetspeak.
- **Estimar la duración de una charla.** El tiempo de lectura es una referencia aproximada para guiones; hablando se va más despacio, normalmente 130–150 palabras por minuto.

Para codificar texto en lugar de darle forma, mira el [conversor Base64](/es/tools/base64-converter/) o el [generador de hashes](/es/tools/hash-generator/).
