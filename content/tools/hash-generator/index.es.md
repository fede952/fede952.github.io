---
title: "Generador de hash y verificador de checksum"
description: "Genera hashes MD5, SHA-1, SHA-256 y SHA-512 de un texto, o verifica un archivo descargado con su checksum publicado. Funciona en tu navegador, sin subir nada."
intro: "Escribe o pega un texto para obtener sus hashes **MD5, SHA-1, SHA-256 y SHA-512** mientras tecleas, o **verifica un archivo**: elige una descarga, pega el checksum de la página del autor y obtén un claro **coincide o no coincide**. Los archivos de cualquier tamaño se procesan por partes en un worker en segundo plano y nunca salen de tu dispositivo."
date: 2026-02-03
lastmod: 2026-10-26
reviewed: false
keywords: ["generador de hash", "generador sha256", "generador md5", "hash sha512 online", "hash sha1", "texto a sha256", "calcular checksum", "calculadora de hash online"]
tags: ["criptografía", "hash", "herramientas-desarrollo", "herramienta"]
app_category: "DeveloperApplication"
tool_partial: "hash-generator"
howto:
  - "Escribe o pega tu texto en **Texto de entrada**. Los cuatro hashes se recalculan con cada pulsación."
  - "Lee el resultado que necesitas: **MD5** (32 caracteres hexadecimales), **SHA-1** (40), **SHA-256** (64) o **SHA-512** (128)."
  - "Pulsa **Copiar** junto a un hash para llevarlo al portapapeles."
  - "Para compararlo con un hash que te hayan dado, pégalos en un editor o compáralos carácter a carácter: un solo carácter distinto significa una entrada distinta."
  - "Pulsa **Borrar todo** para vaciar la entrada y los resultados."
  - "Para comprobar una descarga, baja hasta **Verificar el checksum de un archivo**, elige el archivo y pega el checksum que da el autor (un hash suelto o la línea de un archivo SHA256SUMS). El algoritmo se elige según su longitud."
faq:
  - q: "¿Qué algoritmo de hash debo usar?"
    a: "Para comprobaciones de integridad, huellas y diseños nuevos, SHA-256 (o SHA-512). MD5 y SHA-1 están rotos en seguridad: existen ataques de colisión prácticos, así que no deben usarse en firmas ni certificados. Siguen sirviendo para usos sin requisitos de seguridad, como claves de caché o para cuadrar un checksum heredado."
  - q: "¿Puedo hacer el hash de una contraseña con esta herramienta?"
    a: "Puedes calcular el SHA-256 de cualquier cadena, pero un hash SHA simple es la forma equivocada de guardar contraseñas: está pensado para ser rápido, y un atacante puede probar miles de millones de intentos por segundo. Los sistemas reales usan una función de hash de contraseñas lenta y con sal, como Argon2id, bcrypt, scrypt o PBKDF2."
  - q: "¿Por qué mi hash es distinto del de otra herramienta?"
    a: "Casi siempre cambia la entrada. Revisa si hay un salto de línea final (`echo` lo añade; usa `echo -n`), espacios, finales de línea de Windows `\\r\\n` o una codificación de texto distinta. Esta herramienta calcula el hash exactamente de los caracteres del cuadro, codificados en UTF-8."
  - q: "¿Puedo calcular el hash de un archivo?"
    a: "Sí. Usa **Verificar el checksum de un archivo** debajo de los hashes de texto. El archivo se lee en tu navegador por bloques en un worker en segundo plano (con la biblioteca hash-wasm, servida desde este sitio), así que funcionan incluso archivos de varios gigabytes sin llenar la memoria, y no se sube nada. En la línea de comandos: `sha256sum archivo` en Linux, `shasum -a 256 archivo` en macOS y `Get-FileHash archivo -Algorithm SHA256` en Windows PowerShell."
  - q: "¿Se puede revertir o descifrar un hash?"
    a: "No. Un hash es una función de un solo sentido: no hay clave ni forma de calcular la entrada a partir de la salida. Las webs que \"descifran MD5\" solo buscan en tablas de hashes precalculados de palabras comunes, y precisamente por eso las entradas cortas o habituales no quedan protegidas con un hash."
  - q: "¿Se envía a algún servidor lo que escribo?"
    a: "No. SHA-1, SHA-256 y SHA-512 se calculan con `crypto.subtle.digest()` y MD5 con una implementación en JavaScript, todo dentro de esta página. No hay peticiones de red con lo que introduces."
---

## Cómo funciona

Con cada cambio, la herramienta lee el cuadro de texto, lo convierte a bytes con `TextEncoder` (UTF-8, así que `é` ocupa dos bytes y un emoji cuatro) y ejecuta cuatro funciones de hash en paralelo con `Promise.all`:

- **SHA-1, SHA-256 y SHA-512** pasan por la **Web Crypto API** nativa del navegador: `crypto.subtle.digest('SHA-256', bytes)` devuelve un `ArrayBuffer`, que se convierte a hexadecimal en minúsculas.
- **MD5** no forma parte de Web Crypto, porque se considera roto, así que lo calcula una implementación compacta en JavaScript de la RFC 1321 sobre los mismos bytes UTF-8.

Los resultados son cadenas hexadecimales cuya longitud fija el algoritmo, sea cual sea el tamaño de la entrada:

| Algoritmo | Tamaño | Caracteres hex | Estado |
|---|---|---|---|
| MD5 | 128 bits | 32 | Roto (colisiones desde 2004) |
| SHA-1 | 160 bits | 40 | Roto (colisión práctica, 2017) |
| SHA-256 | 256 bits | 64 | Seguro, la opción por defecto |
| SHA-512 | 512 bits | 128 | Seguro, más rápido en CPU de 64 bits |

Dos propiedades los hacen útiles. Son **deterministas**: la misma entrada da siempre el mismo hash, en cualquier máquina. Y tienen **efecto avalancha**: cambia un carácter y se invierte aproximadamente la mitad de los bits de salida, así que `Hola` y `hola` tienen SHA-256 totalmente distintos. Los botones `Copiar` usan la Clipboard API, con una alternativa para navegadores antiguos.

### Texto, no archivos

La entrada es el texto del cuadro, así que los hashes solo coinciden con los de las herramientas de línea de comandos si los bytes coinciden exactamente. `printf '¡Hola, Mundo!' | sha256sum` y esta herramienta coinciden; `echo '¡Hola, Mundo!' | sha256sum` no, porque `echo` añade un salto de línea.

## Cómo verificar una descarga

Un checksum demuestra que tu archivo es, bit a bit, el archivo del que el autor calculó el hash. Detecta descargas cortadas o dañadas y archivos manipulados en un mirror.

1. **Toma el checksum de la fuente oficial** — la página de descargas o las notas de versión del proyecto, mejor por HTTPS. Un checksum alojado junto al archivo en el mismo mirror prueba poco: quien puede cambiar el archivo puede cambiar también el checksum.
2. **Descarga el archivo**, abre **Verificar el checksum de un archivo** en esta página y elígelo.
3. **Pega el checksum esperado.** Puedes pegar la línea entera de un archivo `SHA256SUMS`, una línea `SHA256 (archivo) = …` o la salida de PowerShell; la herramienta encuentra el hash y el algoritmo.
4. **Lee el resultado.** *Coincide* significa que el archivo es idéntico. *No coincide* significa que no lo es: bórralo y descárgalo de nuevo del sitio oficial. Basta un carácter distinto; no existe "casi igual".
5. **Prefiere SHA-256 o SHA-512.** MD5 y SHA-1 siguen detectando daños accidentales, pero se pueden fabricar colisiones a propósito, así que no demuestran que el archivo no se haya cambiado.

Para la comprobación más fuerte, algunos proyectos firman además sus archivos de checksums con GPG o Sigstore. Verificar esa firma demuestra quién publicó el checksum; esta herramienta comprueba que tu archivo coincide con él.

## Casos de uso

- **Verificar un checksum.** Muchos proyectos publican el SHA-256 de una cadena de versión o de una configuración pequeña: pega el texto y compara.
- **Depurar firmas y APIs.** Comprueba el hash que una API espera para un payload, o el SHA-256 que entra en una firma AWS Signature V4 o en la verificación de un webhook.
- **Claves de caché y deduplicación.** Obtén un identificador estable a partir del texto de una URL, una consulta o un documento.
- **Aprender criptografía.** Observa el efecto avalancha en directo, compara las longitudes de los resúmenes y entiende por qué MD5 y SHA-1 están retirados para seguridad.
- **Cuadrar datos heredados.** Recrea un valor MD5 o SHA-1 que guardó un sistema antiguo para migrarlo a algo más robusto.
