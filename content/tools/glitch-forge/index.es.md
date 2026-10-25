---
title: "Efecto Glitch para Fotos Online"
description: "Añade efectos glitch a tus fotos: RGB shift, pixel sorting, scanlines y ruido digital, con presets VHS y cyberpunk. PNG a resolución completa, sin subidas."
intro: "**GlitchForge** convierte una foto en glitch art: separación cromática RGB, pixel sorting, scanlines de CRT y ruido digital, dosificados con cuatro controles o con presets de un clic. La imagen se procesa en un canvas de tu navegador y se exporta como PNG a resolución completa."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["efecto glitch", "glitch art online", "efecto rgb split", "pixel sorting online", "efecto vhs foto", "efecto cyberpunk foto", "efecto aberración cromática", "foto glitch"]
tags: ["imágenes", "diseño", "creatividad", "herramienta"]
app_category: "MultimediaApplication"
tool_file: "/tools/glitch-forge/"
tool_title: "GlitchForge, generador de glitch art"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Arrastra un JPEG, PNG o WebP al área del canvas o haz clic para elegirlo."
  - "Prueba primero un preset: **VHS**, **Cyberpunk**, **Corrupt** o **Subtle**."
  - "Ajusta con los controles: **Amount** (contraste, ruido y cortes), **RGB Shift**, **Scanlines** y **Pixel Sort**. La vista previa se actualiza mientras arrastras."
  - "Pulsa **Download Cyberpunk Image** para guardar `glitchforge-export.png` a la resolución original."
  - "Pulsa **Reset Image** para devolver todos los controles a cero y empezar de nuevo."
faq:
  - q: "¿Se sube mi foto a algún sitio?"
    a: "No. La imagen se dibuja en un canvas HTML y cada efecto se calcula sobre sus píxeles en JavaScript, en tu navegador. No se envía nada a ningún servidor, así que puedes usarlo con fotos personales."
  - q: "¿Qué resolución tiene la descarga?"
    a: "La original. La vista previa se reduce para caber en pantalla, pero la exportación vuelve a dibujar la imagen a su ancho y alto completos, aplica los mismos ajustes y guarda un PNG sin pérdida."
  - q: "¿Por qué la descarga se ve algo distinta de la vista previa?"
    a: "El ruido y los cortes horizontales son aleatorios y se generan de nuevo para la exportación, a otro tamaño. El carácter del efecto es el mismo, pero los píxeles de ruido y la posición de las barras cambian, igual que cada vez que mueves un control."
  - q: "¿Qué es el pixel sorting?"
    a: "Un efecto popularizado por artistas glitch como Kim Asendorf: los píxeles de una zona se reordenan por brillo y las áreas claras se estiran en franjas. GlitchForge ordena en vertical los tramos de píxeles luminosos, así que las luces se derriten hacia abajo mientras las zonas oscuras quedan intactas."
  - q: "¿Qué es el efecto RGB shift?"
    a: "Imita la aberración cromática o una señal analógica desalineada: el canal rojo se desplaza a la derecha y el azul a la izquierda, dejando bordes de color en cada contorno. Al máximo, el desplazamiento es el 4 % del ancho de la imagen."
  - q: "¿Puedo usar las imágenes con fines comerciales?"
    a: "El resultado es tu propia foto transformada por un algoritmo, así que los derechos son los de la imagen original. La herramienta no añade marcas de agua ni reclama nada sobre el resultado."
---

## Cómo funciona

Al cargar un archivo, la imagen se dibuja en un canvas escalado para la vista previa y se guarda una copia limpia de sus píxeles (`getImageData`). Cada vez que se mueve un control, los efectos se aplican a una copia nueva de esos píxeles, en este orden:

1. **Amount: contraste y ruido.** Cada canal de color se aleja del gris medio con un factor de contraste de hasta 1,6×, luego se añade ruido aleatorio de hasta ±20 niveles y el valor se limita a 0–255.
2. **RGB shift.** Se copia el búfer de píxeles; para cada píxel, el rojo se lee de un píxel *shift* columnas a la izquierda y el azul de *shift* columnas a la derecha, con *shift* = RGB × 4 % del ancho. El verde no se mueve, lo que produce los bordes rojos y azules.
3. **Pixel sort.** Se recorre de arriba abajo una de cada dos columnas. Donde la luminancia (0,299 R + 0,587 G + 0,114 B, los pesos Rec. 601) supera un umbral de 1 − Sort, el tramo de píxeles luminosos, limitado a la mitad de la altura × Sort, se recoge y se reordena de oscuro a claro.
4. **Scanlines.** Se dibujan encima líneas negras horizontales de un píxel de alto, cada 2–4 píxeles, con una opacidad de hasta el 50 %, como en una pantalla CRT.
5. **Cortes.** Cuando Amount supera el 25 %, hasta ocho franjas horizontales finas y aleatorias se copian y se desplazan de lado: el típico fallo de "tracking" del VHS.

Los presets son solo posiciones de los controles:

| Preset | Amount | RGB | Scanlines | Sort |
|---|---|---|---|---|
| VHS | 45 | 60 | 70 | 10 |
| Cyberpunk | 65 | 80 | 40 | 35 |
| Corrupt | 85 | 50 | 20 | 90 |
| Subtle | 20 | 25 | 15 | 5 |

El renderizado se programa con `requestAnimationFrame`, así que arrastrar un control redibuja como mucho una vez por fotograma. Para la descarga, un segundo canvas al tamaño original ejecuta la misma cadena de efectos y se guarda con `toDataURL('image/png')`.

## Casos de uso

- **Portadas, carteles y miniaturas** con estética synthwave, VHS o cyberpunk sin abrir un editor pesado.
- **Publicaciones en redes.** Una foto de perfil con glitch o un fondo para historias destaca en el feed.
- **Recursos para juegos y apps.** Crea fondos de pantalla corrupta, pantallas de error o texturas de interfaz "hackeada".
- **Exploración de diseño.** El pixel sorting y el desplazamiento de canales generan rápidamente texturas abstractas a partir de fotos corrientes.
- **Enseñar procesamiento de imágenes.** Cada control es una operación clásica sobre píxeles; activarlos uno a uno muestra que una imagen es solo una matriz de números.
