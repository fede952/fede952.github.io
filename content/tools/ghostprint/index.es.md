---
title: "Test de Huella del Navegador: ¿Eres Único?"
description: "Mira la huella que tu navegador entrega a cada web (canvas, GPU WebGL, audio, fuentes, pantalla, zona horaria) y una estimación de unicidad. Sin subidas."
intro: "**GhostPrint** lee las mismas señales que los scripts de rastreo y antifraude leen en silencio en la mayoría de webs, te las muestra una a una y estima hasta qué punto hacen identificable tu navegador. Cada prueba se ejecuta en esta página; no se envía nada."
date: 2026-07-06
lastmod: 2026-10-24
reviewed: false
keywords: ["test huella digital navegador", "browser fingerprinting", "huella digital del navegador", "canvas fingerprint", "webgl fingerprint", "cómo de rastreable soy", "soy único en internet", "rastreo sin cookies"]
tags: ["privacidad", "seguridad", "fingerprinting", "herramienta"]
app_category: "SecurityApplication"
tool_file: "/tools/ghostprint/"
tool_title: "GhostPrint, test de huella del navegador"
tool_height: 2200
tool_sandbox: "allow-scripts allow-same-origin allow-downloads allow-modals"
tool_allow: "clipboard-write"
howto:
  - "Abre la página: el análisis empieza solo. GhostPrint examina 12 señales en unos dos segundos y las va listando según las lee; **Re-scan** lo repite."
  - "Lee el veredicto y la cifra principal, por ejemplo \"1 in 2.1 million\": cuántos navegadores habría que revisar, según la estimación, para encontrar uno con tu misma huella."
  - "Recorre las tarjetas de señales: cada una muestra el valor en bruto, los bits de información identificativa que aporta y una explicación de una línea."
  - "Apunta tu **Fingerprint ID**. Abre esta página en una ventana privada o tras borrar las cookies: el ID no cambia, y esa es precisamente la gracia del fingerprinting."
  - "Usa **Download shareable card** o **Copy summary** para comparar navegadores o enseñar a un compañero por qué borrar las cookies no basta."
faq:
  - q: "¿Qué es el browser fingerprinting?"
    a: "Es una forma de reconocer un navegador sin guardar nada en él. Un script lee decenas de pequeñas propiedades (tamaño de pantalla, fuentes instaladas, modelo de GPU, cómo dibuja tu equipo una imagen oculta) y las combina en un identificador. No interviene ninguna cookie, así que el identificador sobrevive a la navegación privada, al borrado de cookies y a casi todos los botones de \"borrar datos\"."
  - q: "¿La puntuación de unicidad es una medición?"
    a: "Es una estimación. A cada señal se le asigna un peso fijo en bits, según cuánta información identificativa suele aportar ese tipo de señal en la investigación publicada sobre fingerprinting; los pesos se suman, se descuentan un 18 % porque las señales están correlacionadas y el resultado se limita a unos 5.500 millones, el número de usuarios de internet. GhostPrint no te compara con una base de datos de otros visitantes, y por eso puede funcionar sin recoger nada."
  - q: "¿El modo incógnito o privado evita el fingerprinting?"
    a: "No. El modo privado borra cookies e historial al cerrarlo, pero tu GPU, tus fuentes, tu pantalla y el renderizado del canvas siguen siendo los mismos, así que la huella también. Puedes comprobarlo: el Fingerprint ID que ves aquí no cambia en una ventana privada."
  - q: "¿Qué navegadores resisten mejor el fingerprinting?"
    a: "Tor Browser hace que todos sus usuarios parezcan iguales, el enfoque más eficaz. Brave aleatoriza por sitio las lecturas de canvas, WebGL y audio. Firefox tiene `privacy.resistFingerprinting`, que estandariza muchos valores. Safari reduce algunas señales por defecto. Chrome y Edge exponen casi todas salvo que añadas una extensión."
  - q: "¿Sirven las extensiones anti-fingerprinting?"
    a: "Algunas sí, sobre todo las que aleatorizan canvas y audio, pero una extensión poco común puede convertirse a su vez en un rasgo distintivo. Bloquear una señal por completo, como WebGL, también puede hacerte más raro. El objetivo es parecer común, no invisible."
  - q: "¿Se envía algún dato mío a vuestro servidor?"
    a: "No. Todas las pruebas se ejecutan en JavaScript dentro de esta página y el resultado se muestra en local. La herramienta no hace peticiones a ningún servicio de analítica ni de fingerprinting, y la tarjeta descargable se genera en un canvas en tu navegador."
---

## Cómo funciona

GhostPrint recoge doce señales. Cinco se *miden* activamente dibujando o procesando algo; el resto se leen de API estándar del navegador.

**Señales de renderizado**

- **Canvas.** La página dibuja texto (con un emoji y letras acentuadas), un rectángulo relleno y un arco en un canvas oculto de 240 × 60, lo exporta con `toDataURL()` y calcula el hash del resultado con FNV-1a de 32 bits. Las fuentes, el suavizado, la GPU y el controlador gráfico dejan diferencias mínimas en los píxeles, así que el hash cambia de un equipo a otro. Una salida vacía o diminuta se considera bloqueada.
- **WebGL.** Abre un contexto WebGL, lee el fabricante y el renderizador de la GPU sin enmascarar mediante `WEBGL_debug_renderer_info` y los combina en un hash con la versión de WebGL, la del lenguaje de sombreado, los tamaños máximos de textura y renderbuffer, el límite de atributos de vértice y la lista completa de extensiones admitidas.
- **Audio.** Un `OfflineAudioContext` procesa un segundo de onda triangular de 10 kHz a través de un compresor dinámico. La suma de 1.000 muestras de salida se convierte en hash; las diferencias de coma flotante entre pilas de audio hacen que varíe según el dispositivo. A los 900 ms la prueba se rinde.
- **Fuentes.** Una cadena de prueba oculta de 72 px se mide en las tres familias genéricas (serif, sans-serif, monospace) y luego con cada una de **53 fuentes comunes** delante. Si cambia la anchura o la altura, la fuente está instalada. Tu conjunto de fuentes refleja el sistema operativo, su idioma y el software que tienes instalado.

**Señales de solo lectura:** cadena user-agent, plataforma, resolución de pantalla con relación de píxeles y profundidad de color, zona horaria con desfase UTC, idiomas preferidos, núcleos de CPU, memoria del dispositivo y puntos táctiles, preferencias de esquema de color y de movimiento reducido, y el estado de cookies, Do-Not-Track y Global Privacy Control.

### De las señales a "1 entre N"

Cada señal tiene un peso fijo en bits:

| Señal | Bits |
|---|---|
| Huella de canvas | 8 |
| Fuentes | 0,45 por fuente detectada, máx. 8 |
| Modelo de GPU (WebGL) | 7 |
| User agent | 6 (8 si es inusualmente largo) |
| Huella de audio | 5 |
| Pantalla, zona horaria | 2 cada una |
| Idiomas, hardware | 1,5 cada uno |
| Plataforma | 1 |
| Preferencias de visualización, indicadores de privacidad | 0,5 cada uno |

Una señal bloqueada o aleatorizada cuenta 0 bits. El total se multiplica por **0,82** para tener en cuenta la correlación (una GPU concreta suele implicar una plataforma concreta, por ejemplo) y se convierte en "1 entre 2^bits", con un tope de 5.500 millones. Los veredictos son *Blending in* por debajo de 10 bits, *Identifiable* desde 10, *Highly unique* desde 18 y *Ghost-level exposure* desde 28.

El **Fingerprint ID** son tres hashes FNV-1a de 4 caracteres: del user agent, la plataforma y la pantalla; de los hashes de WebGL y canvas; y de todas las señales juntas. Que se mantenga igual en ventanas privadas es la demostración práctica.

## Casos de uso

- **Entender por qué "borrar cookies" no es privacidad.** Haz el test, bórralo todo, vuelve a hacerlo: mismo ID.
- **Comparar navegadores y ajustes.** Prueba Firefox con `resistFingerprinting`, Brave, Tor Browser y tu navegador de siempre, y mira qué tarjetas bajan a 0 bits.
- **Formación en seguridad.** Una demo de 30 segundos de las tarjetas de GPU y fuentes hace el concepto tangible para compañeros no técnicos.
- **Revisar supuestos antifraude.** Quien desarrolla sistemas de puntuación de riesgo puede ver qué señales son estables y cuáles se bloquean con facilidad.
- **Compartir el resultado.** La tarjeta descargable de 1200 × 630 (tamaño de vista previa en redes) muestra tu veredicto, entropía e ID sin exponer los valores en bruto.
