---
title: "Analizar cabeceras de correo: SPF y DKIM"
description: "Pega las cabeceras de un correo para seguir su ruta, comprobar SPF, DKIM y DMARC y detectar remitentes falsos. Gratis, privado y en tu navegador."
intro: "Pega las **cabeceras completas** de un correo sospechoso para ver de dónde viene de verdad. El analizador reconstruye la **ruta servidor a servidor** con el retraso de cada salto, lee los resultados **SPF, DKIM, DMARC y ARC** que registró tu proveedor y señala las **discrepancias** entre From, Reply-To y Return-Path. Todo se analiza en tu navegador: las cabeceras no se envían a ninguna parte."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["analizar cabeceras de correo", "ver cabeceras email", "comprobar remitente de un correo", "saber si un correo es falso", "cabeceras gmail mostrar original", "comprobar spf dkim dmarc correo", "rastrear origen de un correo", "email spoofing detectar"]
tags: ["security", "email", "phishing", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/email-header-analyzer/"
tool_title: "Analizador de cabeceras de correo"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Copia las cabeceras desde tu programa de correo (mira **Cómo obtener las cabeceras** más abajo) — o todo el código fuente del mensaje: el cuerpo se ignora."
  - "Pégalas en el cuadro. El análisis se hace al pegar; pulsa **Analizar** para repetirlo."
  - "Lee el **veredicto** y las **señales**, de la más grave a la menos. Cada una explica qué significa y cuándo es inofensiva."
  - "Revisa la tabla **Identidad del remitente**: los dominios de From, Reply-To y Return-Path normalmente pertenecen a la misma organización."
  - "Sigue la **ruta** desde el primer servidor hasta tu buzón. Los retrasos largos y los servidores inesperados merecen una segunda mirada."
faq:
  - q: "¿Se suben mis cabeceras a algún sitio?"
    a: "No. Las cabeceras las analiza el JavaScript de esta página y la herramienta no hace peticiones de red. Puedes abrir la página, desconectarte de internet y sigue funcionando."
  - q: "¿Puede el analizador decirme con certeza si un correo es phishing?"
    a: "Ninguna herramienta puede. Las cabeceras muestran cómo viajó el mensaje y si el dominio del remitente lo respaldó. Un mensaje puede superar todas las comprobaciones y aun así ser una estafa enviada desde un dominio parecido que pertenece al estafador: mira también el dominio del From y los enlaces (la herramienta Link Hazmat de este sitio los revisa)."
  - q: "¿Por qué algunas cabeceras no se consideran fiables?"
    a: "Todo lo que hay por debajo de las líneas Received que añadió tu proveedor lo puede escribir cualquiera por el camino, incluido el remitente. El analizador se fía de la cabecera Authentication-Results de tu proveedor y trata el resto como afirmaciones. Si pegas un mensaje reenviado como adjunto, analiza el original adjunto, no el mensaje de reenvío."
  - q: "¿Qué significan SPF, DKIM y DMARC?"
    a: "SPF indica qué servidores pueden enviar correo por un dominio. DKIM es una firma criptográfica que añade el dominio remitente. DMARC se supera cuando SPF o DKIM pasan para el mismo dominio que aparece en From, y dice a los receptores qué hacer cuando ninguno pasa. ARC registra los resultados originales cuando una lista o un reenvío modifican el mensaje."
  - q: "¿Por qué un boletín auténtico tiene otro Return-Path?"
    a: "Los servicios de envío mandan correos en nombre de empresas y recogen los rebotes en un dominio o subdominio propio. Por eso un Return-Path o un Message-ID de otro dominio solo se marca como leve: importa cuando llega junto a un DMARC fallido o a un Reply-To de un dominio ajeno."
  - q: "¿Por qué algunas horas van hacia atrás?"
    a: "Cada servidor anota la hora de su propio reloj, y algunos relojes están mal. El analizador lo indica como desfase de reloj y muestra igualmente la ruta en orden."
---

## Cómo obtener las cabeceras

La mayoría de los programas de correo ocultan las cabeceras. Abre primero el mensaje y después:

- **Gmail (web)** — abre el mensaje, haz clic en el botón **⋮ Más** junto a Responder y elige **Mostrar original**. Pulsa **Copiar en el portapapeles**. La app de Gmail para móvil no muestra las cabeceras: usa un navegador.
- **Outlook para Windows (clásico)** — haz doble clic en el mensaje para abrirlo en su propia ventana y luego **Archivo → Propiedades**. Las cabeceras están en el cuadro **Encabezados de Internet** de abajo: haz clic dentro, pulsa Ctrl+A y Ctrl+C.
- **Nuevo Outlook y Outlook en la web** — abre el mensaje, haz clic en **… Más acciones → Ver → Ver detalles del mensaje** y copia el texto.
- **Apple Mail (Mac)** — selecciona el mensaje y elige **Visualización → Mensaje → Todas las cabeceras** (⇧⌘H), o **Visualización → Mensaje → Código fuente** (⌥⌘U) para el mensaje completo. Mail en iPhone y iPad no muestra las cabeceras.
- **Thunderbird** — selecciona el mensaje y elige **Ver → Código fuente del mensaje** (Ctrl+U, ⌘U en Mac). Copia todo lo que hay antes de la primera línea vacía, o simplemente todo.

Los nombres de los menús pueden variar un poco según la versión. No te reenvíes el correo sospechoso para ver sus cabeceras: el reenvío crea un mensaje nuevo con cabeceras nuevas.

## Cómo funciona

### La ruta: las líneas Received se leen de abajo arriba

Cada servidor que maneja un mensaje añade arriba una línea **Received**, así que la más antigua queda al final. El analizador las invierte en una línea temporal desde el primer servidor hasta tu buzón y muestra el tiempo entre saltos. Solo son fiables las líneas que añadió tu proveedor: un remitente puede escribir líneas Received falsas debajo de ellas, y por eso el analizador se basa en los resultados de autenticación y no en el origen declarado.

### Autenticación: lo que tu proveedor ya comprobó

Cuando llega un mensaje, tu proveedor comprueba **SPF**, **DKIM** y **DMARC** y anota los resultados en la cabecera **Authentication-Results**. El analizador lee esa cabecera y comprueba también la **alineación**: una firma DKIM o un SPF superado solo te protegen si corresponden a la misma organización que la dirección From. No consulta el DNS ni verifica firmas por su cuenta, porque el proveedor ya lo hizo en la entrega, con las claves válidas en ese momento.

### Discrepancias de identidad

El nombre visible es texto libre, así que los estafadores suelen poner en él una dirección de confianza (`"ayuda@tubanco.example" <x@random.test>`). El analizador compara los dominios de **From**, **Reply-To**, **Return-Path** y del **Message-ID**, y explica qué diferencias son normales en los servicios de envío y cuáles delatan a un impostor.

## Casos de uso

- **Un correo sospechoso** — comprueba si el mensaje del "banco" o de la "mensajería" viene de verdad de ese dominio antes de pulsar nada.
- **Soporte y equipos de seguridad** — clasifica rápido los avisos de phishing y pega la línea temporal en un ticket.
- **Entregabilidad** — descubre por qué tus boletines fallan en DMARC o acaban en spam, y qué salto retrasa la entrega.
- **Para aprender** — entiende SPF, DKIM y DMARC con ejemplos realistas y ponte a prueba con el [test de phishing](../phishing-quiz/).
