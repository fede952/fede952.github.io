---
title: "Decodificar JWT y Verificar la Firma"
description: "Decodifica cualquier JSON Web Token, lee sus claims y su caducidad y verifica firmas HS256, RS256, PS256 o ES256 con la Web Crypto API, en tu navegador."
intro: "Pega un **JSON Web Token** para ver su cabecera y su payload, revisar `exp`, `nbf` e `iat` en hora legible y verificar la firma con un secreto o una clave pública. La decodificación y la verificación ocurren en tu navegador: el token nunca se envía."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["decodificar jwt", "jwt decoder", "verificar firma jwt", "jwt online", "validar token jwt", "jwt rs256", "caducidad jwt", "jwt debugger"]
tags: ["seguridad", "herramientas-desarrollo", "jwt", "herramienta"]
app_category: "DeveloperApplication"
tool_file: "/tools/jwt-inspector/"
tool_title: "TokenLens: decodificador JWT y verificador de firmas"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-read; clipboard-write"
howto:
  - "Pega un token en el cuadro o pulsa **Paste** para leerlo del portapapeles. **Load sample** carga un token HS256 de ejemplo."
  - "El token se divide en sus tres partes de colores y se decodifica al instante: la cabecera y el payload aparecen como JSON resaltado."
  - "Mira las etiquetas de estado: algoritmo, `typ`, `kid` y si el token está caducado o aún no es válido. La tabla de claims traduce `exp`, `nbf` e `iat` a fechas locales."
  - "Para verificar, pega el **secreto HMAC** en HS256/384/512 (marca *Secret is Base64URL-encoded* si lo está) o la **clave pública** del firmante en PEM o JWK para los algoritmos RS, PS y ES."
  - "Pulsa **Verify signature**. Verde significa que la firma coincide con esa clave y el token no se ha modificado; rojo, clave equivocada o token alterado."
faq:
  - q: "¿Es seguro pegar aquí un JWT de producción?"
    a: "La herramienta funciona íntegramente en tu navegador y no hace peticiones de red con el token, así que por nuestra parte no queda registrado nada. Aun así, un access token válido es una contraseña con fecha de caducidad: quien lo vea puede usarlo hasta que expire. Mejor tokens caducados o de prueba, y nunca en una herramienta que no puedas inspeccionar."
  - q: "¿Qué diferencia hay entre decodificar y verificar un JWT?"
    a: "Decodificar solo deshace la codificación Base64URL de la cabecera y el payload, y lo puede hacer cualquiera: un JWT está firmado, no cifrado. Verificar es recalcular la firma sobre `header.payload` con la clave y comprobar que coincide con el tercer segmento. Solo la verificación te dice que el token lo emitió quien tiene la clave y que no se ha modificado."
  - q: "¿Qué algoritmos puede verificar?"
    a: "HS256, HS384 y HS512 (HMAC con secreto compartido); RS256, RS384 y RS512 (RSA PKCS#1 v1.5); PS256, PS384 y PS512 (RSA-PSS); y ES256, ES384 y ES512 (ECDSA sobre P-256, P-384 y P-521). Los tokens con `alg: none` u otros algoritmos se decodifican pero no se verifican."
  - q: "¿Dónde encuentro la clave pública de un token RS256?"
    a: "La mayoría de proveedores de identidad publican sus claves como JWKS en una URL del tipo `https://issuer/.well-known/jwks.json`. Busca la entrada cuyo `kid` coincide con la cabecera del token y pega ese objeto JWK. También sirve una clave pública PEM (`-----BEGIN PUBLIC KEY-----`)."
  - q: "¿Por qué no se verifica un token con \"alg\": \"none\"?"
    a: "Porque no hay nada que verificar: el token afirma no estar firmado. Aceptar ese tipo de tokens es una vulnerabilidad clásica; el servidor debe decidir qué algoritmos acepta en lugar de fiarse de la cabecera. El inspector muestra el algoritmo bien visible precisamente para que llame la atención."
  - q: "La firma es válida pero la API sigue rechazando el token. ¿Por qué?"
    a: "Una firma válida es solo una de las comprobaciones. Los servidores validan también `exp`, `nbf`, el emisor (`iss`), la audiencia (`aud`) y a menudo los scopes. Revisa las etiquetas de estado y la tabla de claims: un token caducado o una audiencia incorrecta son la causa más habitual."
  - q: "¿La herramienta guarda el secreto o la clave que pego?"
    a: "No. Las claves se importan con `crypto.subtle.importKey` como no extraíbles, se usan una vez para verificar y se descartan con la página. No se escribe nada en el almacenamiento del navegador."
---

## Cómo funciona

### Decodificación

Un JWT son tres segmentos Base64URL unidos por puntos: `header.payload.signature`. El inspector divide la cadena, comprueba que haya exactamente tres segmentos, convierte el Base64URL en Base64 estándar (cambiando `-` por `+` y `_` por `/` y restaurando el relleno `=`), decodifica los bytes como UTF-8 y lee la cabecera y el payload con `JSON.parse`. Una entrada mal formada produce un error concreto en vez de una pantalla en blanco.

Los claims registrados del payload se explican en una tabla. Los claims de tiempo `exp` (caducidad), `nbf` (no antes de) e `iat` (emitido en) son valores **NumericDate**, segundos desde el 1 de enero de 1970 UTC, así que se convierten a tu hora local y a una descripción relativa como "in 23 min" o "3 days ago". La barra de estado avisa de un token caducado, de uno que aún no es válido y de uno sin `exp`.

### Verificación

La verificación usa la **Web Crypto API** integrada en el navegador (`crypto.subtle`), no una librería criptográfica en JavaScript:

- La entrada firmada es la cadena ASCII `header.payload` tal como aparece en el token. No se vuelve a codificar, por eso un token editado a mano no pasa la verificación.
- **HS256/384/512**: el secreto se importa como clave HMAC en bruto con SHA-256, SHA-384 o SHA-512, y `crypto.subtle.verify('HMAC', …)` comprueba el MAC.
- **RS256/384/512**: la clave pública se importa como `RSASSA-PKCS1-v1_5` con el hash correspondiente.
- **PS256/384/512**: se importa como `RSA-PSS` y se verifica con una sal igual a la longitud del hash (32, 48 o 64 bytes), como exige la RFC 7518.
- **ES256/384/512**: se importa como `ECDSA` sobre P-256, P-384 o P-521. Las firmas ECDSA de JWS son la concatenación en bruto `r‖s`, el formato que espera Web Crypto, así que no hace falta convertir a DER.

Las claves públicas se pueden dar en **PEM/SPKI** (el Base64 entre las líneas `BEGIN/END PUBLIC KEY` se decodifica a DER) o como objeto **JWK** en JSON. Las claves importadas no son extraíbles y solo existen durante la verificación.

### Una trampa habitual

Los secretos HMAC suelen configurarse como cadenas Base64. Si tu backend decodifica el secreto antes de firmar, marca *Secret is Base64URL-encoded*; si no, la misma cadena visible produce una clave distinta y la firma no coincide.

## Casos de uso

- **Depurar la autenticación.** Descubre por qué una petición devuelve 401: `exp` caducado, `aud` incorrecto, un scope que falta o un token firmado con otra clave.
- **Comprobar la integración con un proveedor de identidad.** Decodifica el ID token de un login OAuth/OIDC y verifícalo con la JWKS del proveedor antes de escribir el backend.
- **Revisiones de seguridad y pentests.** Detecta tokens con `alg: none`, duraciones excesivas, datos sensibles en el payload o un `kid` que apunta adonde no debe.
- **Rotación de claves.** Confirma que los tokens emitidos tras una rotación se verifican con la nueva clave pública y los antiguos con la anterior.
- **Formación.** Muestra cómo está hecho un token y por qué Base64URL es una codificación, no un cifrado.
