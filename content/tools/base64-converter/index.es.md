---
title: "Codificar y Decodificar Base64 (UTF-8)"
description: "Codifica texto a Base64 o decodifica Base64 y Base64URL a texto, con soporte UTF-8 completo para acentos y emoji. Gratis, al instante, en tu navegador."
intro: "Convierte texto a **Base64** y al revés. La codificación es segura para UTF-8 y la decodificación acepta también la variante **Base64URL** que usan los JWT y las API web, con o sin relleno `=`. Nada de lo que pegas sale de esta página."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["codificar base64", "decodificar base64", "base64 decoder", "base64 online", "decodificar base64url", "base64 a texto", "base64 utf-8", "convertidor base64"]
tags: ["codificación", "herramientas-desarrollo", "base64", "herramienta"]
app_category: "DeveloperApplication"
tool_partial: "base64-converter"
howto:
  - "Escribe o pega en **Texto de entrada**: texto normal para codificar o una cadena Base64 para decodificar."
  - "Pulsa **Codificar a Base64** para convertir el texto en Base64. Los acentos, la ñ, los alfabetos no latinos y los emoji se codifican en UTF-8."
  - "Pulsa **Decodificar Base64** para volver a texto. Se aceptan Base64 estándar, Base64URL (`-` y `_`), relleno ausente y saltos de línea."
  - "Lee el resultado en **Resultado** y pulsa **Copiar** para llevarlo al portapapeles."
  - "Si los bytes decodificados no son UTF-8 válido, la herramienta te avisa: probablemente son datos binarios (una imagen, un fichero comprimido o una clave) y no texto."
faq:
  - q: "¿Para qué sirve Base64?"
    a: "Base64 representa datos binarios con 64 caracteres ASCII imprimibles, para que puedan viajar por sistemas que solo manejan texto: adjuntos de correo (MIME), data URLs en HTML y CSS, payloads JSON, cabeceras de autenticación HTTP Basic, Secrets de Kubernetes y las tres partes de un JSON Web Token."
  - q: "¿Base64 es cifrado?"
    a: "No. Es una codificación sin clave: cualquiera puede decodificarla al instante, como demuestra esta página. Nunca uses Base64 para ocultar contraseñas o secretos; los Secrets de Kubernetes, por ejemplo, solo están codificados en Base64, no cifrados, salvo que actives el cifrado en reposo."
  - q: "¿Qué diferencia hay entre Base64 y Base64URL?"
    a: "Base64URL (RFC 4648, sección 5) sustituye `+` por `-` y `/` por `_` para que el resultado sea seguro en URLs y nombres de archivo, y normalmente elimina el relleno `=`. Lo usan los JWT y muchas API. Esta herramienta decodifica ambos; al codificar produce Base64 estándar."
  - q: "¿Por qué el texto decodificado sale ilegible?"
    a: "O la entrada no era texto desde el principio (por ejemplo, una imagen o un flujo gzip), o el texto original se codificó con otro juego de caracteres, como Latin-1 en lugar de UTF-8. La herramienta decodifica como UTF-8 y te avisa cuando los bytes no son UTF-8 válido."
  - q: "¿Por qué Base64 ocupa un tercio más que el original?"
    a: "Cada 3 bytes de entrada se convierten en 4 caracteres Base64, porque cada carácter lleva 6 bits (2⁶ = 64). Es un 33 % más, además de hasta dos caracteres `=` de relleno al final. Una imagen de 30 KB se convierte en una data URL de 40 KB."
  - q: "¿Se envía a algún sitio el texto que pego?"
    a: "No. La codificación y la decodificación usan las funciones integradas del navegador `btoa`, `atob`, `TextEncoder` y `TextDecoder` dentro de esta página. No se sube ni se guarda nada."
---

## Cómo funciona

### Codificación

La función `btoa()` de JavaScript solo entiende caracteres del rango Latin-1, así que llamarla directamente sobre `"Ciudad €"` lanza un error. La herramienta lo evita codificando de la forma correcta:

1. `TextEncoder` convierte el texto en **bytes UTF-8**: `à` pasa a ser `C3 A0` y `€` `E2 82 AC`.
2. Cada byte se convierte en un carácter de un byte, y `btoa()` transforma esa cadena de bytes en Base64.

Base64 trabaja con grupos de **3 bytes = 24 bits**, divididos en cuatro valores de 6 bits, cada uno asociado a un carácter del alfabeto `A–Z a–z 0–9 + /`. Si la longitud de la entrada no es múltiplo de 3, el último grupo se completa con `=`:

| Texto | Bytes UTF-8 | Base64 |
|---|---|---|
| `Man` | `4D 61 6E` | `TWFu` |
| `Ma` | `4D 61` | `TWE=` |
| `M` | `4D` | `TQ==` |
| `é` | `C3 A9` | `w6k=` |

### Decodificación

La decodificación invierte el proceso con cierta tolerancia para la entrada del mundo real:

- Se eliminan los espacios y saltos de línea (MIME corta el Base64 cada 76 caracteres).
- Los caracteres **Base64URL** `-` y `_` vuelven a ser `+` y `/`, y se restaura el relleno `=` que falte, así que puedes pegar un segmento de JWT tal cual.
- `atob()` convierte el Base64 en bytes y `TextDecoder` con `fatal: true` los interpreta como UTF-8. Si los bytes no son UTF-8 válido, la herramienta muestra igualmente una decodificación aproximada pero avisa de que probablemente son datos binarios.
- Una cadena cuya longitud dividida entre 4 da resto 1 nunca puede ser Base64 válido, y se rechaza con un mensaje claro.

## Casos de uso

- **Leer un JWT a mano.** Pega el segmento central de un token para ver sus claims en JSON (para comprobar la firma, usa JWT Inspector).
- **Kubernetes y Docker.** Decodifica los valores de un manifiesto Secret o codifica uno antes de ponerlo en `data:`.
- **Autenticación HTTP Basic.** Decodifica una cabecera `Authorization: Basic …` para ver el `usuario:contraseña` que lleva, o construye una para una petición de prueba.
- **Data URLs y correo.** Inspecciona URIs `data:` y partes MIME en el código fuente de un correo.
- **Depurar APIs.** Muchas API codifican en Base64 campos binarios o JSON anidado; decodifícalos para ver qué se envió realmente.
