---
title: "Analizador de cabeceras de seguridad y CSP"
description: "Pega cabeceras de respuesta HTTP o una Content-Security-Policy para detectar cabeceras ausentes, reglas CSP débiles y cookies inseguras, con su solución. Local."
intro: "Pega las **cabeceras de respuesta** de una página —de `curl -sI` o de las DevTools del navegador— o una **Content-Security-Policy** sola. El analizador revisa **HSTS**, **CSP**, **X-Content-Type-Options**, la protección contra el enmarcado, **Referrer-Policy**, **Permissions-Policy**, **COOP**, **CORS** y cada **Set-Cookie**, explica cada problema y muestra la solución. No hace **ninguna petición de red**: solo lee lo que pegas, así que también sirve para sitios de staging e intranet."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["comprobar cabeceras de seguridad", "csp evaluator", "verificar content security policy", "cabeceras de seguridad http", "analizador csp", "comprobar hsts", "revisar cabeceras de respuesta", "x-frame-options"]
tags: ["seguridad", "csp", "http", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/security-headers/"
tool_title: "Analizador de cabeceras de seguridad y CSP"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Copia las cabeceras de respuesta de la página que quieres revisar: ejecuta `curl -sI https://example.com` en una terminal o abre DevTools → **Red**, recarga, selecciona la petición de la página y copia sus **Cabeceras de respuesta**."
  - "Pégalas en **Cabeceras de respuesta o CSP**. También puedes pegar solo una política (`default-src 'self'; …`) o una etiqueta `<meta http-equiv=\"Content-Security-Policy\">`."
  - "El resultado aparece al pegar: una nota y después todos los hallazgos ordenados de **Grave** a **Correcto**, cada uno con la cabecera a la que afecta y qué cambiar."
  - "En **Content-Security-Policy** se listan las directivas con sus orígenes; los arriesgados se resaltan en rojo o ámbar y los seguros en verde."
  - "Pulsa **Copiar informe** para pegar los hallazgos en un ticket o una pull request. Prueba **Ejemplo débil** y **Ejemplo sólido** para ver la diferencia."
faq:
  - q: "¿La herramienta se conecta a mi web?"
    a: "No. No descarga ninguna URL: solo analiza el texto que pegas, en tu navegador. Así tu servidor no aparece en registros de terceros y puedes revisar sitios no públicos, como staging, intranet o localhost."
  - q: "¿Por qué pegar las cabeceras en lugar de introducir una URL?"
    a: "Las reglas CORS del navegador impiden que una página web lea otra URL salvo que lo haga un servidor por ti, y ese servidor vería todos los sitios que pruebas. Pegar la salida de `curl -sI` es igual de rápido y todo queda en local."
  - q: "¿Qué hace débil una Content-Security-Policy?"
    a: "Los problemas habituales son `'unsafe-inline'` en script-src (deja ejecutar scripts en línea inyectados), los orígenes de esquema como `https:` o `data:` y el comodín `*` (admiten scripts de casi cualquier sitio), CDN permitidas que alojan endpoints JSONP o el antiguo AngularJS, y la falta de object-src o base-uri. Una investigación de Google vio que la mayoría de las políticas basadas en listas de hosts se pueden saltar; los nonces con 'strict-dynamic' lo evitan."
  - q: "¿Qué es una CSP estricta?"
    a: "Una política que permite los scripts mediante un nonce aleatorio (o un hash) en lugar de por host, más `'strict-dynamic'` para que los scripts de confianza puedan cargar otros. Es el enfoque que recomiendan Google y OWASP contra XSS. El ejemplo de \"Cómo funciona\" es un buen punto de partida: despliégalo primero como Content-Security-Policy-Report-Only y corrige lo que notifique."
  - q: "¿Cómo se calcula la nota?"
    a: "Se parte de 100 y se restan 20 puntos por cada hallazgo grave, 10 por cada medio y 4 por cada leve; las notas informativas y lo correcto no restan. A+ exige no tener hallazgos graves ni medios. La nota es un resumen rápido, no una certificación: lee los hallazgos, porque su impacto depende de tu sitio."
  - q: "¿Siguen haciendo falta X-Frame-Options y X-XSS-Protection?"
    a: "En los navegadores actuales, frame-ancestors de la CSP sustituye a X-Frame-Options, pero enviar ambas no perjudica y cubre los antiguos, así que la herramienta acepta cualquiera de las dos. X-XSS-Protection está obsoleta: los navegadores eliminaron el filtro que controlaba, por lo que se recomienda quitarla o enviar 0."
  - q: "¿Qué atributos de las cookies revisa?"
    a: "Secure (solo se envía por HTTPS), HttpOnly (oculta a JavaScript), SameSite (limita el envío entre sitios, una defensa contra CSRF) y las reglas de los prefijos __Host- y __Secure-. Una cookie con SameSite=None pero sin Secure la rechazan los navegadores y se marca como grave."
---

## Cómo funciona

### Pegar, analizar, comprobar

El texto pegado se divide en líneas de cabecera. Se tienen en cuenta líneas de estado como `HTTP/2 200`, las pseudocabeceras de HTTP/2 y las líneas partidas; si pegas una cadena de redirecciones, solo se analiza la última respuesta. Las cabeceras repetidas como `Set-Cookie` se revisan una a una. Si el texto empieza por una directiva CSP, o es una etiqueta `<meta>` de CSP, solo se analiza la política.

Después, cada cabecera se compara con el comportamiento actual de los navegadores y con las recomendaciones de OWASP, MDN y la especificación CSP. Cada hallazgo tiene una gravedad, la cabecera a la que afecta y una solución concreta.

### Las comprobaciones de la CSP

La política se descompone en directivas y orígenes. El analizador determina qué directiva rige de verdad los scripts (`script-src`, o `default-src` si falta) y los plugins (`object-src` hereda de `default-src`; `base-uri` y `form-action` no heredan nada). Marca `'unsafe-inline'` y `'unsafe-eval'`, comodines, orígenes de esquema, hosts por HTTP, hosts permitidos que ofrecen JSONP o versiones arbitrarias de bibliotecas, nonces cortos, `'strict-dynamic'` sin nonce y los errores de sintaxis que los navegadores ignoran en silencio: palabras clave sin comillas (`self` en vez de `'self'`), puntos y coma que faltan, directivas duplicadas, desconocidas y obsoletas.

### Una política estricta para empezar

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'self'
```

Genera un nonce aleatorio nuevo (al menos 128 bits) en cada respuesta y añade `nonce="{RANDOM}"` a cada etiqueta `<script>`. Envíala primero como `Content-Security-Policy-Report-Only`, corrige lo que falle y después aplícala.

## Casos de uso

- **Antes de un lanzamiento.** Revisa las cabeceras de un sitio de staging, al que los escáneres online no llegan.
- **Pull requests y auditorías.** Pega las cabeceras antes y después de un cambio y copia el informe en la revisión.
- **Aprender CSP.** Entiende por qué cada origen de una política es o no un riesgo, directiva a directiva.
- **Notas de pentest y bug bounty.** Convierte una respuesta capturada en una lista de hallazgos de cabeceras con su solución.
- **Revisión de cookies.** Comprueba que las cookies de sesión siguen siendo Secure, HttpOnly y SameSite tras actualizar el framework.
