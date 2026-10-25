---
title: "Generador de Hash: MD5, SHA-256, SHA-512"
description: "Genera hashes MD5, SHA-1, SHA-256 y SHA-512 de cualquier texto mientras escribes, con soporte UTF-8 y copia en un clic. Calculado en tu navegador."
intro: "Escribe o pega un texto y obtén a la vez sus hashes **MD5, SHA-1, SHA-256 y SHA-512**, actualizados mientras tecleas. La familia SHA la calcula la Web Crypto API de tu navegador; nada de lo que introduces se envía a ningún sitio."
date: 2026-02-03
lastmod: 2026-10-24
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
faq:
  - q: "¿Qué algoritmo de hash debo usar?"
    a: "Para comprobaciones de integridad, huellas y diseños nuevos, SHA-256 (o SHA-512). MD5 y SHA-1 están rotos en seguridad: existen ataques de colisión prácticos, así que no deben usarse en firmas ni certificados. Siguen sirviendo para usos sin requisitos de seguridad, como claves de caché o para cuadrar un checksum heredado."
  - q: "¿Puedo hacer el hash de una contraseña con esta herramienta?"
    a: "Puedes calcular el SHA-256 de cualquier cadena, pero un hash SHA simple es la forma equivocada de guardar contraseñas: está pensado para ser rápido, y un atacante puede probar miles de millones de intentos por segundo. Los sistemas reales usan una función de hash de contraseñas lenta y con sal, como Argon2id, bcrypt, scrypt o PBKDF2."
  - q: "¿Por qué mi hash es distinto del de otra herramienta?"
    a: "Casi siempre cambia la entrada. Revisa si hay un salto de línea final (`echo` lo añade; usa `echo -n`), espacios, finales de línea de Windows `\\r\\n` o una codificación de texto distinta. Esta herramienta calcula el hash exactamente de los caracteres del cuadro, codificados en UTF-8."
  - q: "¿Puedo calcular el hash de un archivo?"
    a: "No con esta página: trabaja con texto. Para archivos usa la línea de comandos: `sha256sum archivo` en Linux, `shasum -a 256 archivo` en macOS o `Get-FileHash archivo -Algorithm SHA256` en PowerShell de Windows."
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

## Casos de uso

- **Verificar un checksum.** Muchos proyectos publican el SHA-256 de una cadena de versión o de una configuración pequeña: pega el texto y compara.
- **Depurar firmas y APIs.** Comprueba el hash que una API espera para un payload, o el SHA-256 que entra en una firma AWS Signature V4 o en la verificación de un webhook.
- **Claves de caché y deduplicación.** Obtén un identificador estable a partir del texto de una URL, una consulta o un documento.
- **Aprender criptografía.** Observa el efecto avalancha en directo, compara las longitudes de los resúmenes y entiende por qué MD5 y SHA-1 están retirados para seguridad.
- **Cuadrar datos heredados.** Recrea un valor MD5 o SHA-1 que guardó un sistema antiguo para migrarlo a algo más robusto.
