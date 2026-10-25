---
title: "Comprobar SPF, DKIM y DMARC de un dominio"
description: "Comprueba los registros SPF, DKIM y DMARC de un dominio, cuenta las consultas SPF frente al límite de 10, revisa claves DKIM y BIMI y obtén correcciones."
intro: "Escribe un dominio para calificar su **autenticación de correo**. La herramienta lee el registro **SPF** y cuenta sus consultas DNS **a través de cada include** frente al límite de 10, lee la **política DMARC**, el porcentaje, las direcciones de informes y la alineación, mide el **tamaño de las claves DKIM** y revisa **MX** y **BIMI**. Cada problema trae un **registro de ejemplo** para corregirlo. Las consultas DNS van al resolver DNS-over-HTTPS de Cloudflare, solo cuando pulsas Comprobar."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["comprobar spf", "comprobar dmarc", "comprobar dkim", "verificar spf dkim dmarc", "registro spf comprobar", "registro dmarc ejemplo", "spf demasiadas consultas dns", "longitud clave dkim", "política dmarc reject", "registro bimi"]
tags: ["security", "email", "dns", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/spf-dmarc-checker/"
tool_title: "Comprobador de SPF, DKIM y DMARC"
tool_height: 1150
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Escribe un **dominio** (o pega una dirección de correo: solo se usa la parte después de @)."
  - "Opcional: escribe tus **selectores DKIM**, separados por comas. Sin ellos, la herramienta prueba nombres de selector habituales."
  - "Pulsa **Comprobar**. Es el único momento en que se envían consultas DNS."
  - "Lee la **nota** y cada sección: SPF con el recuento de consultas y el árbol de include, etiquetas DMARC, claves DKIM, MX y BIMI."
  - "En **Correcciones sugeridas**, copia los registros de ejemplo, sustituye las partes entre corchetes angulares y consulta a tu proveedor de correo antes de publicarlos."
faq:
  - q: "¿Qué se envía y a quién?"
    a: "Al pulsar Comprobar, tu navegador envía consultas DNS del dominio (sus registros TXT para SPF, _dmarc, selectores DKIM y BIMI, y sus registros MX) al resolver público DNS-over-HTTPS de Cloudflare, cloudflare-dns.com. Como cualquier petición web, revela a Cloudflare tu dirección IP y el user-agent del navegador. No se envía nada a este sitio, y nada sale antes de pulsar el botón."
  - q: "¿Por qué SPF tiene un límite de 10 consultas?"
    a: "El estándar SPF (RFC 7208) limita a 10 por comprobación los mecanismos que necesitan una consulta DNS — include, a, mx, ptr, exists y el modificador redirect —, contados a través de todos los include anidados. Los receptores que llegan al límite se detienen con un error permanente, así que SPF falla para todo tu correo, no solo para los remitentes de más. ip4, ip6 y all no cuentan."
  - q: "¿Por qué no encuentra la clave DKIM si mi correo está firmado?"
    a: "Las claves DKIM están bajo un nombre de selector que elige tu proveedor (selector._domainkey.tudominio), y el DNS no permite listarlas. La herramienta solo prueba algunos nombres habituales. Busca tu selector en la etiqueta s= de una cabecera DKIM-Signature (el analizador de cabeceras de correo de este sitio la muestra) y escríbelo."
  - q: "¿Basta con p=none?"
    a: "Es el primer paso correcto: recibes informes sin afectar a la entrega. Pero no impide que nadie suplante tu dominio. Cuando los informes muestren que tus remitentes legítimos pasan, cambia a p=quarantine y después a p=reject."
  - q: "¿~all o -all?"
    a: "Ambos marcan como no autorizados a los servidores no incluidos. Con DMARC en quarantine o reject, los receptores actúan igualmente según el resultado DMARC, así que ~all es una opción habitual y segura; -all es más estricto, y algunos receptores podrían rechazar el mensaje solo por eso, antes de evaluar DMARC."
  - q: "¿Los registros de ejemplo están listos para pegar?"
    a: "Son puntos de partida creados a partir de tus registros actuales. Hay que sustituir las partes entre corchetes angulares, y solo tú o tu proveedor sabéis qué servicios envían por tu dominio. Consulta a tu proveedor y vuelve a comprobar cuando el DNS se haya actualizado."
---

## Cómo funciona

### SPF: contar las consultas como los receptores

La herramienta obtiene los registros TXT del dominio y se queda con el que empieza por `v=spf1`. Después lo recorre término a término. Cada `include`, `a`, `mx`, `ptr`, `exists` y `redirect` suma una consulta, y cada `include` se obtiene y se recorre a su vez, así que también cuentan los proveedores anidados. El total se compara con el límite de 10 de la RFC 7208. También se señalan los include hacia dominios sin SPF, más de dos consultas que no devuelven nada, los bucles de include, el mecanismo desaconsejado `ptr` y el calificador de `all`.

### DMARC: política, cobertura e informes

El registro de `_dmarc.<dominio>` se analiza etiqueta por etiqueta. Un subdominio sin registro propio hereda el del dominio principal y su política `sp=`, igual que hacen los receptores. La nota depende de la política (`none`, `quarantine`, `reject`), de `pct`, de si hay informes agregados (`rua`) y de si las direcciones de informes de otro dominio han publicado el registro de autorización necesario (RFC 7489, sección 7.1).

### DKIM: tamaño de la clave a partir de la clave pública

Para cada selector encontrado se decodifica el valor `p=` y se lee el tamaño del módulo RSA de la clave. Los receptores no deben aceptar claves de menos de 1024 bits (RFC 8301); el tamaño recomendado es 2048 bits. Las claves vacías aparecen como revocadas, y se reconocen las claves Ed25519.

### MX y BIMI

Los registros MX indican dónde recibe correo el dominio; un "null MX" (`0 .`) significa que no acepta ninguno. BIMI (`default._bimi`) es opcional y solo funciona con una política DMARC que bloquea al 100 %.

## Casos de uso

- **Antes de enviar boletines** — asegúrate de que SPF, DKIM y DMARC pasan para llegar a la bandeja de entrada.
- **Tras añadir un servicio de correo** — comprueba que el nuevo `include:` no ha llevado SPF por encima de 10 consultas.
- **Proteger un dominio** — pasa DMARC de `p=none` a `p=reject` con confianza y protege los dominios que nunca envían correo.
- **Revisiones de seguridad** — revisa la protección contra suplantación de los dominios de un proveedor o de tu organización.
- **Investigar un correo sospechoso** — mira qué publica el dominio del remitente y lee después el mensaje con el [analizador de cabeceras de correo](../email-header-analyzer/).
