---
title: "Comprobador de Contraseñas y Filtraciones"
description: "Comprueba lo segura que es una contraseña (entropía, tiempo de ataque por fuerza bruta) y si aparece en filtraciones conocidas, con k-anonimato."
intro: "**PassFort** revisa una contraseña que ya usas: su entropía, cuánto tardaría un ataque por fuerza bruta, los patrones que conviene evitar y, si lo pides, si ha aparecido en una **filtración de datos** conocida. El análisis de seguridad no sale de esta página; la comprobación opcional de filtraciones envía solo 5 caracteres del hash de la contraseña. ¿Necesitas una contraseña nueva? Usa el [Generador de Contraseñas Aleatorias](/es/tools/password-generator/)."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["comprobar seguridad contraseña", "comprobador de contraseñas", "contraseña filtrada", "mi contraseña ha sido filtrada", "entropía de contraseña", "cuánto se tarda en descifrar mi contraseña", "test de contraseña", "have i been pwned contraseña"]
tags: ["seguridad", "contraseñas", "privacidad", "herramienta"]
app_category: "SecurityApplication"
tool_file: "/tools/pass-fort/"
tool_title: "PassFort: comprobador de seguridad y filtraciones de contraseñas"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write"
howto:
  - "Escribe o pega la contraseña que quieres revisar en la pestaña **Auditor**, que se abre primero. El botón del ojo la muestra u oculta."
  - "Mira el medidor de entropía, el tiempo estimado de descifrado y la lista de comprobaciones: lo que aparezca en rojo conviene corregirlo antes de reutilizar esa contraseña."
  - "Si quieres, pulsa **Check against known breaches** para saber si esa contraseña exacta ha aparecido en alguna filtración. No se envía nada hasta que lo pulsas."
  - "Para crear una frase de paso o una contraseña nueva, abre la pestaña **Generator**. Elige la longitud (de 8 a 128 caracteres) y los grupos de caracteres: mayúsculas, minúsculas, dígitos y símbolos."
  - "Para algo que puedas escribir y recordar, marca **Passphrase Mode** y elige de 3 a 8 palabras. Para una contraseña maestra, usa al menos 6."
  - "Pulsa **Generate Password** hasta que te guste el resultado; el botón del portapapeles lo copia. Pégalo directamente en tu gestor de contraseñas."
faq:
  - q: "¿Es seguro escribir mi contraseña real en este comprobador?"
    a: "Sí. El auditor es JavaScript que se ejecuta dentro de esta página: nunca envía por la red lo que escribes, y el valor desaparece en cuanto vacías el campo o cierras la pestaña. Puedes confirmarlo en las herramientas de desarrollo del navegador (pestaña Red) mientras escribes. Si lo prefieres, prueba una contraseña que *siga el mismo patrón* que la real. La única excepción es la comprobación opcional de filtraciones, y solo cuando pulsas su botón: envía 5 caracteres del hash SHA-1 de la contraseña, nunca la contraseña (mira la siguiente pregunta)."
  - q: "¿Cómo funciona la comprobación de filtraciones sin revelar mi contraseña?"
    a: "Usa el modelo de k-anonimato del servicio Pwned Passwords de Have I Been Pwned. PassFort calcula en tu navegador el hash SHA-1 de la contraseña y envía solo sus 5 primeros caracteres hexadecimales a `api.pwnedpasswords.com`. El servicio responde con las cerca de 1.000 terminaciones de hash que comparten ese prefijo, con su número de filtraciones, y PassFort busca la coincidencia en local. La petición pide además relleno (`Add-Padding: true`), de modo que todas las respuestas tienen un tamaño parecido sea cual sea el resultado. El servicio nunca ve la contraseña ni su hash completo; sí ve tu dirección IP, como en cualquier petición web. La comprobación solo se hace cuando pulsas el botón."
  - q: "¿Cuántos bits de entropía necesita una contraseña segura?"
    a: "Para cuentas protegidas con un hash lento y con sal, 60–70 bits de entropía *aleatoria* resisten mucho tiempo un ataque de fuerza bruta offline. Para la contraseña maestra del gestor o el cifrado de disco, apunta a 80–100 bits. Una contraseña aleatoria de 16 caracteres con los cuatro grupos da unos 103 bits; una frase de paso de PassFort de 7 palabras, unos 72 bits."
  - q: "¿Frase de paso o contraseña aleatoria: cuál es mejor?"
    a: "Ambas son robustas si las palabras o los caracteres los elige al azar una máquina. Las contraseñas de caracteres aleatorios concentran más entropía por carácter y son ideales cuando las escribe tu gestor de contraseñas. Las frases de paso son más fáciles de teclear y recordar, así que son la mejor opción para las pocas contraseñas que debes introducir a mano, siempre que uses suficientes palabras."
  - q: "¿Por qué el comprobador dice \"siglos\" para una contraseña que sé que es débil?"
    a: "La estimación supone que cada carácter se eligió al azar. Un atacante real empieza por diccionarios, listas de contraseñas filtradas y reglas como \"mayúscula al principio, año al final\", así que `Verano2024!` cae en segundos aunque su entropía bruta parezca aceptable. PassFort solo detecta algunos patrones evidentes (empezar por 123, abc, password, qwerty, 111 o aaa); para una contraseña inventada por una persona, toma la puntuación como un límite máximo."
  - q: "¿Qué significa \"10 mil millones de intentos por segundo\"?"
    a: "Es la velocidad de ataque que asume la estimación: aproximadamente una GPU moderna contra un hash rápido y sin sal como MD5 o NTLM. Contra bcrypt, scrypt o Argon2 el atacante es miles de veces más lento, así que los tiempos reales suelen ser mayores. Contra un formulario de inicio de sesión con límite de intentos, muchísimo mayores."
  - q: "¿PassFort guarda o registra las contraseñas que genera?"
    a: "No. Las contraseñas generadas solo existen en la memoria de la página hasta que las copias. No hay cuentas, almacenamiento ni servidor detrás de la herramienta. Guarda la contraseña en un gestor: al cerrar la pestaña ya no se puede recuperar."
  - q: "¿Qué longitud debe tener una contraseña en 2026?"
    a: "Si la genera y guarda un gestor de contraseñas, usa al menos 16 caracteres aleatorios: no te cuesta nada. Si tienes que memorizarla, usa una frase de paso de 6 o más palabras aleatorias. La longitud gana a las reglas de complejidad: una contraseña larga y aleatoria solo con minúsculas es más fuerte que una corta llena de símbolos."
---

## Cómo funciona

### El generador

Cada carácter procede de `crypto.getRandomValues()`, el generador de números aleatorios criptográficamente seguro de la Web Crypto API, que el navegador alimenta con la fuente de entropía del sistema operativo. Nunca se usa `Math.random()`.

Para convertir un número aleatorio de 32 bits en una posición dentro del conjunto de caracteres, PassFort usa **muestreo por rechazo**: los valores que caen en el último "bloque" incompleto del rango de 32 bits se descartan y se vuelven a sortear. El simple `aleatorio % tamaño` haría algo más probables los primeros caracteres del conjunto. El sesgo es mínimo, pero no hay motivo para aceptarlo.

Los cuatro grupos son 26 mayúsculas, 26 minúsculas, 10 dígitos y 26 símbolos (`!@#$%^&*()_+-=[]{}|;:,.<>?`), 88 caracteres en total. Cada carácter aporta log₂(88) ≈ **6,46 bits** de entropía:

| Longitud | Los cuatro grupos | Solo minúsculas |
|---|---|---|
| 12 | ≈ 77 bits | ≈ 56 bits |
| 16 | ≈ 103 bits | ≈ 75 bits |
| 20 (por defecto) | ≈ 129 bits | ≈ 94 bits |

Los caracteres se sortean de forma independiente, así que no está *garantizado* que una contraseña corta contenga todos los grupos marcados. Genera otra si un sitio exige, por ejemplo, un dígito.

### El modo frase de paso

El modo frase de paso elige palabras de una lista interna de **1.207 palabras en inglés** con el mismo índice aleatorio sin sesgo, pone en mayúscula la inicial de cada una y las une con guiones (por ejemplo `Harbor-Canyon-Crisp-Velvet`). Cada palabra aporta log₂(1207) ≈ **10,24 bits**: 4 palabras dan unos 41 bits, 6 palabras unos 61 bits y el máximo de 8 palabras unos 82 bits.

Es menos por palabra que una lista Diceware completa de 7.776 palabras (12,9 bits); por eso en esta página recomendamos al menos 6 palabras para cualquier cosa importante. Las mayúsculas y los guiones son fijos, así que no añaden entropía.

### El auditor

El auditor estima el tamaño del "alfabeto" del que sale tu contraseña: 26 si contiene una minúscula, +26 por mayúsculas, +10 por dígitos y +33 por cualquier otro carácter. La entropía es entonces `longitud × log₂(alfabeto)`.

El tiempo de descifrado es lo que se tarda en probar las 2^entropía combinaciones a **10¹⁰ intentos por segundo**, mostrado en unidades comprensibles hasta "siglos". El medidor se llena a los 100 bits y pasa de rojo a naranja, amarillo y verde a los 25, 50 y 75 bits. Debajo aparecen ocho comprobaciones: al menos 8 y 12 caracteres, cada clase de caracteres, ningún patrón inicial común y al menos 60 bits.

Es el modelo clásico de "fuerza bruta". Es preciso para contraseñas aleatorias como las del generador y **optimista para las contraseñas que inventa la gente**, porque no detecta palabras de diccionario, nombres ni fechas.

### La comprobación opcional de filtraciones

Una contraseña puede tener mucha entropía y aun así no servir porque se ha filtrado: los atacantes prueban primero las contraseñas filtradas. **Check against known breaches** pregunta a Have I Been Pwned si esa contraseña exacta está en su lista de contraseñas de filtraciones reales, con k-anonimato: solo salen de la página los 5 primeros de los 40 caracteres hexadecimales de su hash SHA-1 (`5BAA6` para `password`), la comparación con los sufijos devueltos se hace en tu navegador y las respuestas llevan relleno para que su tamaño no revele nada. Está desactivada hasta que pulsas el botón, y escribir otra contraseña borra el resultado anterior.

## Casos de uso

- **Cuentas nuevas.** Genera una contraseña de 16–20 caracteres y guárdala en tu gestor de contraseñas. No necesitarás volver a verla.
- **Las contraseñas que tienes que recordar.** La contraseña maestra del gestor, el inicio de sesión del ordenador, el cifrado de disco: usa una frase de paso de 6–8 palabras que puedas teclear sin fallos.
- **Revisar viejos hábitos.** Pega una contraseña que llevas años usando, mira su puntuación y cambia las débiles, empezando por el correo y el banco.
- **Claves Wi-Fi y secretos compartidos.** Las frases de paso WPA2/WPA3 admiten hasta 63 caracteres: una larga y aleatoria no cuesta nada e impide descifrar offline un handshake capturado.
- **Formación y políticas.** La tabla de arriba y el medidor en vivo hacen tangible la entropía cuando explicas a tus compañeros por qué "8 caracteres con un símbolo" ya no es una buena política.
