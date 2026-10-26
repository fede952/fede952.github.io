---
title: "Generador de contraseñas y frases seguras"
description: "Genera contraseñas aleatorias robustas de hasta 64 caracteres, o frases diceware con listas de palabras en 6 idiomas. Entropía exacta y nada se envía."
intro: "Un **generador de contraseñas seguras** de un clic: elige la longitud y los tipos de caracteres para una contraseña aleatoria, o cambia a **Frase de contraseña** para una serie de palabras aleatorias (en español, inglés, alemán, italiano, francés o portugués). Todo sale del generador criptográfico de tu navegador, con su robustez exacta en bits."
date: 2026-02-03
lastmod: 2026-10-26
reviewed: false
keywords: ["generador de contraseñas seguras", "generador de contraseñas aleatorias", "crear contraseña segura", "contraseña aleatoria online", "generador de claves", "contraseña de 16 caracteres", "generar contraseña"]
tags: ["seguridad", "contraseñas", "herramienta"]
app_category: "SecurityApplication"
tool_partial: "password-generator"
howto:
  - "Mueve el control **Longitud** (de 8 a 64 caracteres). Cada vez que lo mueves se genera al instante una contraseña nueva."
  - "Desmarca los grupos de caracteres que el sitio no acepte: mayúsculas **A–Z**, minúsculas **a–z**, dígitos **0–9** o símbolos **!@#**."
  - "Mira la línea bajo la contraseña: muestra la entropía en bits y una etiqueta (Débil, Buena, Fuerte)."
  - "Pulsa **Generar contraseña** para obtener otra; el botón de copiar junto al campo la pasa al portapapeles."
  - "Pégala en tu gestor de contraseñas *antes* de cerrar la página: el generador no guarda ningún historial."
  - "Para algo que tengas que escribir o recordar, elige **Frase de contraseña**: indica el número de palabras, la lista (sigue el idioma de la página) y el separador. Seis palabras en español dan 66 bits; siete, 77."
faq:
  - q: "¿Este generador de contraseñas es realmente aleatorio?"
    a: "Sí. Cada carácter se elige con `crypto.getRandomValues()`, el generador de números aleatorios criptográficamente seguro del navegador, con muestreo por rechazo para que todos los caracteres del conjunto tengan exactamente la misma probabilidad. No usa `Math.random()`, que es predecible y no sirve para secretos."
  - q: "¿Puede la web ver las contraseñas que genero?"
    a: "No. El generador son unas pocas líneas de JavaScript que se ejecutan en tu navegador: no hay peticiones a ningún servidor, ni registros, ni almacenamiento. Si te desconectas de internet tras cargar la página sigue funcionando, que es la prueba más sencilla."
  - q: "¿Qué longitud debo elegir?"
    a: "Con los cuatro grupos, 16 caracteres dan unos 104 bits de entropía, muy por encima de lo que puede alcanzar un ataque de fuerza bruta. Usa 20 o más para cuentas muy sensibles si el sitio lo permite. Baja de 12 solo si un sistema antiguo te obliga."
  - q: "¿Por qué mi contraseña no tiene ningún símbolo si los símbolos están activados?"
    a: "Cada carácter se sortea de forma independiente entre todo el conjunto, así que la contraseña no está obligada a incluir uno de cada tipo. Con 16 caracteres casi siempre los tendrá. Si un sitio la rechaza por faltar un símbolo o un dígito, pulsa Generar otra vez."
  - q: "¿Qué significan Débil, Buena y Fuerte?"
    a: "Son franjas de entropía: menos de 60 bits es Débil, de 60 a 90 bits Buena y 90 bits o más Fuerte. Como la contraseña se genera al azar, el número es exacto, a diferencia de los medidores que intentan adivinar la entropía de una contraseña que escribes tú."
  - q: "¿Tengo que memorizar estas contraseñas?"
    a: "No, guárdalas en un gestor de contraseñas y deja que las rellene. Para los uno o dos secretos que debas memorizar, como la contraseña maestra del gestor, usa el modo **Frase de contraseña**: seis o siete palabras aleatorias son mucho más fáciles de escribir y recordar que 16 caracteres aleatorios, con una robustez parecida."
  - q: "¿Qué listas de palabras usa el modo de frase de contraseña?"
    a: "El inglés usa la EFF Large Wordlist (7776 palabras, unos 12,9 bits por palabra, CC BY 4.0). El alemán usa la lista de-7776 de dys2p (7776 palabras, publicada bajo CC0 y licencias equivalentes al dominio público). Italiano, español, francés y portugués usan las listas BIP-39 (2048 palabras, 11 bits por palabra) tal como se publican en la biblioteca python-mnemonic de Trezor con licencia MIT. Todas se sirven desde este sitio; Quitar tildes nunca reduce la entropía, porque las palabras BIP-39 siguen siendo distintas sin tildes."
---

## Cómo funciona

El generador forma un conjunto con los grupos marcados: 26 mayúsculas, 26 minúsculas, 10 dígitos y 29 símbolos (`` !@#$%^&*()_+~`|}{[]:;?><,./-= ``), hasta **91 caracteres**. Para cada posición pide a la Web Crypto API un número aleatorio de 32 bits con `crypto.getRandomValues()` y lo convierte en un carácter.

Esa conversión usa **muestreo por rechazo**. 2³² no es múltiplo de 91, así que el simple `aleatorio % 91` haría que unos pocos caracteres fueran algo más probables que el resto. En su lugar, cualquier valor que caiga en la última franja incompleta del rango de 32 bits se descarta y se sortea de nuevo, y todos los caracteres quedan exactamente con la misma probabilidad.

La línea de fuerza no es una suposición. Como cada carácter es uniformemente aleatorio, la entropía es exactamente **longitud × log₂(tamaño del conjunto)**:

| Ajustes | Bits por carácter | 12 car. | 16 car. | 24 car. |
|---|---|---|---|---|
| Los cuatro grupos (91) | 6,51 | 78 | 104 | 156 |
| Letras + dígitos (62) | 5,95 | 71 | 95 | 143 |
| Minúsculas + dígitos (36) | 5,17 | 62 | 83 | 124 |
| Solo dígitos (10) | 3,32 | 40 | 53 | 80 |

La etiqueta es **Débil** por debajo de 60 bits, **Buena** entre 60 y 90 bits y **Fuerte** a partir de 90 bits; la barra se llena a 128 bits. Cambiar la longitud o una casilla regenera la contraseña al momento, así que lo que ves siempre coincide con los ajustes.

La copia usa la Clipboard API asíncrona cuando la página se sirve por HTTPS, con una alternativa para navegadores antiguos. La contraseña solo vive en el campo de texto: recarga la página y desaparece.

### Por qué la entropía es la medida correcta

Un atacante que conozca al detalle este generador, conjunto y longitud incluidos, sigue teniendo que probar de media la mitad de las 2^bits combinaciones. Con 104 bits son unos 10³¹ intentos: incluso a 10 mil millones por segundo tardaría muchísimo más que la edad del universo. Por eso una contraseña de un buen generador es fuerte *por construcción*, mientras que una inventada solo es tan fuerte como pequeño sea el diccionario del atacante.

## Frases de contraseña: palabras aleatorias en lugar de caracteres

Una frase de contraseña son unas cuantas palabras elegidas **al azar** de una lista fija, el método conocido como *diceware*. La robustez solo depende del tamaño de la lista y del número de palabras, nunca de lo ingeniosas que parezcan: cada palabra de una lista de 7776 aporta log₂(7776) ≈ **12,9 bits**, y cada palabra de una lista de 2048, exactamente **11 bits**.

| Palabras | Lista EFF / alemana (7776) | Listas BIP-39 (2048) |
|---|---|---|
| 4 | 51,7 bits | 44 bits |
| 5 | 64,6 bits | 55 bits |
| 6 | 77,5 bits | 66 bits |
| 7 | 90,5 bits | 77 bits |
| 8 | 103,4 bits | 88 bits |

Las palabras se eligen con el mismo muestreo sin sesgo de `crypto.getRandomValues()` que las contraseñas. **Mayúscula inicial** es determinista y no añade entropía; **Añadir una cifra** pone una cifra aleatoria tras una palabra aleatoria y añade log₂(10 × palabras) bits. La lista por defecto sigue el idioma de la página, y cualquier lista se puede usar en cualquier página.

## Casos de uso

- **Registrarte en un servicio nuevo.** Genera 16 o más caracteres, guárdalos en tu gestor y listo.
- **Cambiar una contraseña tras una filtración.** Sustituye una contraseña reutilizada o filtrada por otra única y aleatoria, empezando por tu correo, porque desde ahí se pueden restablecer todas las demás.
- **Claves de API, usuarios de base de datos y cuentas de servicio.** Desmarca los símbolos si una cadena de conexión o un script de shell da problemas con ellos, y sube la longitud para mantener la entropía por encima de 100 bits.
- **Redes Wi-Fi.** Genera una clave de 20–30 caracteres para el router: solo la escribes una vez por dispositivo.
- **Credenciales temporales.** Crea una contraseña de un solo uso para una cuenta de invitado o un documento compartido, y borra la cuenta cuando termines.

Para comprobar la fuerza de una contraseña que ya usas, y si aparece en una filtración de datos conocida, prueba [PassFort](/es/tools/pass-fort/).
