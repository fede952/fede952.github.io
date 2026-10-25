---
title: "Generador de Contraseñas Seguras Aleatorias"
description: "Genera contraseñas aleatorias robustas de hasta 64 caracteres con el generador criptográfico del navegador. Entropía en vivo y copia en un clic."
intro: "Un **generador de contraseñas seguras** de un clic: elige la longitud y los tipos de caracteres y obtén una contraseña aleatoria sacada del generador criptográfico de tu navegador, con su fuerza indicada en bits."
date: 2026-02-03
lastmod: 2026-10-24
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
    a: "No: guárdalas en un gestor de contraseñas y deja que las rellene él. Para la una o dos que sí debes memorizar, como la contraseña maestra del gestor, es más cómoda una frase de paso larga y aleatoria; puedes generarla con PassFort en este sitio."
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

## Casos de uso

- **Registrarte en un servicio nuevo.** Genera 16 o más caracteres, guárdalos en tu gestor y listo.
- **Cambiar una contraseña tras una filtración.** Sustituye una contraseña reutilizada o filtrada por otra única y aleatoria, empezando por tu correo, porque desde ahí se pueden restablecer todas las demás.
- **Claves de API, usuarios de base de datos y cuentas de servicio.** Desmarca los símbolos si una cadena de conexión o un script de shell da problemas con ellos, y sube la longitud para mantener la entropía por encima de 100 bits.
- **Redes Wi-Fi.** Genera una clave de 20–30 caracteres para el router: solo la escribes una vez por dispositivo.
- **Credenciales temporales.** Crea una contraseña de un solo uso para una cuenta de invitado o un documento compartido, y borra la cuenta cuando termines.

Para comprobar la fuerza de una contraseña que ya usas, y si aparece en una filtración de datos conocida, prueba [PassFort](/es/tools/pass-fort/).
