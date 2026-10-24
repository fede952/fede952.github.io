---
title: "Cifrado César: Cifrar y Descifrar (ROT13)"
description: "Cifra y descifra texto con el cifrado César, con cualquier desplazamiento de 1 a 25, ROT13 incluido. Aprende cómo funciona y cómo se rompe. Gratis."
intro: "Desplaza cada letra de tu texto un número fijo de posiciones en el alfabeto, el cifrado que usaba Julio César. Elige un desplazamiento de 1 a 25 (13 da **ROT13**) y después cifra o descifra. Un clásico para acertijos, CTF y para entender por qué los cifrados simples fallan."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["cifrado césar", "descifrar cifrado césar", "código césar", "rot13", "cifrado por desplazamiento", "cifrar texto", "criptografía clásica", "cifrado césar online"]
tags: ["criptografía", "cifrado", "ctf", "herramienta"]
app_category: "EducationalApplication"
tool_partial: "caesar-cipher"
howto:
  - "Escribe o pega tu mensaje en **Texto de entrada**."
  - "Fija el **Desplazamiento** con el control (1–25). César usaba 3; 13 es ROT13."
  - "Pulsa **Cifrar** para desplazar las letras hacia delante, o **Descifrar** para devolverlas la misma cantidad."
  - "Lee el resultado en **Resultado** y pulsa **Copiar** para llevarlo al portapapeles."
  - "Para romper un mensaje desconocido, descífralo con cada desplazamiento hasta que aparezcan palabras legibles: solo hay 25 que probar."
faq:
  - q: "¿Cómo funciona el cifrado César?"
    a: "Cada letra se sustituye por la que está un número fijo de posiciones más adelante en el alfabeto, volviendo a la A después de la Z. Con desplazamiento 3, la A pasa a ser D, la B pasa a E y la Z pasa a C. Para descifrar se retrocede el mismo número."
  - q: "¿Qué es ROT13?"
    a: "ROT13 es el cifrado César con desplazamiento 13. Como el alfabeto inglés tiene 26 letras, aplicarlo dos veces devuelve el texto original, así que la misma operación cifra y descifra. Se usaba en foros para ocultar spoilers y remates de chistes, nunca para seguridad."
  - q: "¿Es seguro el cifrado César?"
    a: "No. Solo hay 25 claves útiles, así que cualquiera puede probarlas todas a mano en segundos. El análisis de frecuencias lo rompe todavía antes: en español la letra más frecuente es la E o la A, y en el texto cifrado aparece desplazada por la clave. Úsalo solo para juegos y docencia."
  - q: "¿Qué pasa con los números, los espacios y las letras acentuadas?"
    a: "Se mantienen sin cambios. La herramienta solo desplaza las 26 letras latinas básicas A–Z y a–z, respetando mayúsculas y minúsculas. Los dígitos, la puntuación, los espacios y letras como á o ñ pasan tal cual."
  - q: "¿Cómo se descifra un cifrado César sin la clave?"
    a: "Por fuerza bruta: descifra con desplazamientos del 1 al 25 y busca el que da un texto legible. En mensajes largos, cuenta las letras: la más frecuente suele corresponder a la E o la A en español, y la distancia entre ambas es el desplazamiento."
  - q: "¿Se envía mi texto a algún sitio?"
    a: "No. El desplazamiento lo calculan unas pocas líneas de JavaScript en esta página y no se sube nada."
---

## Cómo funciona

La herramienta recorre tu texto carácter a carácter y mira su código:

- las mayúsculas `A–Z` (códigos 65–90) se desplazan dentro del alfabeto en mayúsculas;
- las minúsculas `a–z` (códigos 97–122), dentro del alfabeto en minúsculas;
- todo lo demás (dígitos, espacios, puntuación, letras acentuadas y no latinas) se copia sin cambios.

El desplazamiento es aritmética modular sobre la posición *p* de la letra (0 para A, 25 para Z) y la clave *k*:

**cifrado = (p + k) mod 26**, y para descifrar se usa −k.

Como en JavaScript `%` puede devolver números negativos, el código calcula `((p + k) % 26 + 26) % 26`, que mantiene el resultado entre 0 y 25 en ambas direcciones. Después la posición se convierte de nuevo en carácter con su mayúscula o minúscula original.

| Texto claro | Desplazamiento 3 | Desplazamiento 13 (ROT13) |
|---|---|---|
| `HELLO` | `KHOOR` | `URYYB` |
| `Attack at dawn` | `Dwwdfn dw gdzq` | `Nggnpx ng qnja` |
| `Zebra` | `Cheud` | `Mroen` |

### Por qué es tan fácil de romper

El cifrado César tiene un espacio de claves de 25. Un ordenador, o una persona paciente, prueba todas las claves en un momento. Y como cada letra se corresponde siempre con la misma letra, el texto cifrado conserva la huella estadística del idioma: el símbolo más frecuente de un texto cifrado es casi siempre una de las letras más comunes desplazada por la clave. Estas dos debilidades, un espacio de claves diminuto y las frecuencias conservadas, son justo lo que los cifrados modernos como AES están diseñados para evitar.

## Casos de uso

- **Retos CTF y acertijos.** César y ROT13 aparecen constantemente en pruebas capture-the-flag para principiantes, escape rooms y geocaching.
- **Enseñar criptografía.** Muestra cifrado, claves y fuerza bruta con algo que se puede hacer en papel, y luego explica por qué falla.
- **Ocultar spoilers.** ROT13 sigue sirviendo para tapar un remate o una solución ante una lectura accidental.
- **Ejercicios de programación.** Compara tu implementación con esta: la aritmética modular y el tratamiento de mayúsculas son los tropiezos habituales.
- **Curiosidad histórica.** Codifica un mensaje como lo hacían los generales romanos, con desplazamiento 3.
