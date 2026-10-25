---
title: "¿Es Seguro este Enlace? Test de Phishing"
description: "Pega un enlace sospechoso y ve los trucos de phishing de su estructura: IP, logins ocultos con @, dominios punycode, TLD de riesgo. Sin llegar a abrirlo."
intro: "**LinkHazmat** analiza una URL *sin visitarla* y señala los trucos estructurales en los que se apoyan los enlaces de phishing: hosts con dirección IP, logins ocultos con `@`, dominios clon en punycode, TLD de riesgo, marcas en subdominios y parámetros de redirección. Después te da enlaces directos a escáneres de reputación más profundos."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["este enlace es seguro", "comprobar enlace", "detector de phishing", "enlace sospechoso", "escáner de url", "cómo saber si un enlace es seguro", "detectar enlaces de phishing", "verificar link"]
tags: ["seguridad", "phishing", "escáner-url", "herramienta"]
app_category: "SecurityApplication"
tool_partial: "link-hazmat"
howto:
  - "Copia el enlace sospechoso *sin abrirlo*: mantén pulsado o haz clic derecho y elige \"Copiar dirección del enlace\"."
  - "Pégalo en el cuadro y pulsa **INITIATE SCAN** (o Intro). Si falta `http://`, se añade automáticamente."
  - "Lee el veredicto: **LOW RISK**, **SUSPICIOUS** o **HIGH RISK**, con cada truco detectado listado en *Tricks detected*."
  - "Revisa el protocolo, el dominio real y la extensión (TLD) a la que apunta de verdad el enlace: el dominio real suele ser muy distinto de lo que sugiere el texto del enlace."
  - "Para una segunda opinión usa los botones **VirusTotal**, **Google Transparency** o **Urlscan.io**, que abren esos servicios con el enlace ya puesto."
faq:
  - q: "¿Cómo sé si un enlace es seguro antes de pulsarlo?"
    a: "Fíjate en el dominio real, la parte justo antes de la primera `/` simple. En `https://paypal.com.secure-login.xyz/…` el dominio es `secure-login.xyz`, no PayPal. Desconfía de direcciones IP en lugar de nombres, de una `@` en la dirección, de extensiones raras, de muchos guiones y de cualquier página que te pida iniciar sesión tras un correo o un SMS."
  - q: "¿LinkHazmat visita el enlace?"
    a: "No. La URL solo se analiza como texto con el parser `URL` del navegador; no se descarga nada, así que una página maliciosa no puede cargarse ni ejecutar nada. Un tercero solo ve el enlace si pulsas uno de los botones de escáneres externos."
  - q: "¿Un enlace LOW RISK puede ser peligroso igualmente?"
    a: "Sí. Es una comprobación estructural: detecta los trucos que hacen que un enlace *parezca* legítimo, no si el sitio tras un dominio de aspecto normal es malicioso. Un dominio recién registrado con estructura limpia puntúa bajo. Ante la duda, usa los escáneres de reputación o abre el sitio escribiendo tú la dirección."
  - q: "¿Qué es un ataque punycode u homográfico?"
    a: "Los dominios pueden contener letras no latinas, que se guardan en una forma ASCII que empieza por `xn--`. Los atacantes registran clones como `аpple.com` con una а cirílica, que se ve casi igual que el original. LinkHazmat convierte el host a su forma ASCII, de modo que cualquier etiqueta `xn--` queda al descubierto y señalada."
  - q: "¿Por qué una @ en una URL es sospechosa?"
    a: "Todo lo que va antes de una `@` en la parte de autoridad de una URL se interpreta como nombre de usuario, no como host. `https://www.bank.com@evil.example/` lleva en realidad a `evil.example`. Los enlaces legítimos casi nunca la usan, por eso la herramienta suma dos puntos."
  - q: "¿Qué TLD se señalan?"
    a: "`.xyz`, `.top`, `.gq`, `.zip`, `.mov`, `.tk`, `.ml`, `.ga`, `.cf`, `.buzz`, `.icu` y `.cam`: extensiones baratas o gratuitas de registrar que aparecen de forma desproporcionada en los informes de abuso. Muchas webs honradas las usan, así que solo suman un punto."
---

## Cómo funciona

La entrada se analiza con el constructor estándar `URL` del navegador (añadiendo `http://` si no hay esquema). Así se obtienen el protocolo, el nombre de host en forma ASCII y la query string tal como los interpretaría un navegador, algo clave porque el phishing vive de la diferencia entre cómo *parece* una URL y adónde *lleva*.

Cada comprobación suma puntos a una puntuación de riesgo:

| Comprobación | Qué busca | Puntos |
|---|---|---|
| Sin cifrar | `http:` en lugar de `https:` | +1 |
| Host IP | un host como `185.12.4.9` en lugar de un dominio | +2 |
| Login oculto | una `@` en cualquier parte de la entrada | +2 |
| TLD de riesgo | una de 12 extensiones muy abusadas | +1 |
| Dominio largo | nombre de host de más de 50 caracteres | +1 |
| Anidamiento profundo | más de 4 etiquetas, p. ej. `a.b.c.d.com` | +1 |
| Punycode | una etiqueta que empieza por `xn--` (clon internacionalizado) | +2 |
| Muchos guiones | 3 o más guiones en el host | +1 |
| Parámetro de redirección | `redirect=`, `url=`, `goto=`, `next=`, `redir=` o `link=` en la query | +1 |
| Marca en el subdominio | paypal, apple, google, microsoft, amazon, netflix, bank, secure, login, verify o account a la *izquierda* del dominio registrable | +2 |

Una puntuación de **0** es *LOW RISK*, **1–2** es *SUSPICIOUS* y **3 o más** es *HIGH RISK*. La comprobación de marcas solo mira las etiquetas del subdominio: `www.paypal.com` pasa, mientras que `paypal.com.account-check.xyz` (dominio registrable `account-check.xyz`) se señala. El dominio registrable se aproxima con las dos últimas etiquetas, así que sufijos compuestos como `.co.uk` cuentan un nivel de menos.

Los botones de análisis profundo construyen enlaces a la búsqueda de VirusTotal, al estado de Safe Browsing de Google y a la búsqueda de urlscan.io con tu dominio o URL codificados. Solo se abren, en una pestaña nueva, cuando los pulsas.

## Casos de uso

- **Comprobar un enlace de un correo o SMS** que dice ser tu banco, una empresa de mensajería o un servicio de streaming antes de decidir si tocarlo.
- **Soporte y SOC.** Da a un compañero una lectura estructural rápida de un enlace denunciado y pasa luego a los escáneres de reputación.
- **Formación en seguridad.** Pega ejemplos reales de phishing y muestra qué trucos usa cada uno.
- **Enlaces de códigos QR.** Lee un QR con la cámara sin abrirlo y pega aquí primero la URL.
- **Revisar tus propios enlaces.** Asegúrate de que los enlaces de marketing con parámetros de seguimiento o redirección no parezcan phishing a los usuarios prudentes.
