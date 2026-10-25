---
title: "Test de phishing: ¿detectas la estafa?"
description: "Test de phishing gratis: 10 correos, SMS, páginas de acceso, códigos QR y enlaces realistas. Detecta el engaño, mira las señales de alarma y comparte tu nota."
intro: "Diez escenarios realistas — **correos, SMS, páginas de acceso, códigos QR y enlaces** — elegidos al azar de un conjunto de 32. En cada uno decide: **¿phishing o legítimo?** Tras cada respuesta, las señales de alarma se resaltan directamente sobre la simulación, con una explicación de una línea. Todas las marcas y dominios son ficticios y nada de lo que haces sale de tu navegador."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["test de phishing", "quiz phishing", "detectar phishing", "simulación de phishing", "cómo reconocer un correo fraudulento", "test smishing", "formación en ciberseguridad", "test de estafas online"]
tags: ["seguridad", "phishing", "concienciación", "tool"]
app_category: "EducationalApplication"
tool_file: "/tools/phishing-quiz/"
tool_title: "Test de phishing"
tool_height: 980
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write; web-share"
share_scores: 10
share_card_title: "He sacado {score}/10 en el test de phishing"
howto:
  - "Pulsa **Empezar el test**. Recibes 10 escenarios; tres o cuatro son legítimos, así que \"todo es phishing\" no funciona."
  - "Lee la línea de contexto y examina la simulación como harías con la real: la dirección del remitente, adónde lleva de verdad el enlace (pasa el ratón o pon el foco en el botón), la barra de direcciones, el nombre del adjunto."
  - "Responde **Phishing** o **Legítimo**. Las señales de alarma (o las pistas de un mensaje auténtico) se numeran sobre la simulación y se explican debajo."
  - "Al final obtienes una puntuación, un nivel y los temas que repasar, con enlaces a herramientas útiles para cada uno."
  - "Usa **Compartir mi puntuación** para enviar el resultado: el texto compartido solo contiene la puntuación y un enlace."
faq:
  - q: "¿Son reales las empresas del test?"
    a: "No. Todas las marcas, personas, teléfonos y dominios son inventados, y todas las direcciones web usan dominios reservados para documentación (.example, .test) o el rango de IP de documentación 192.0.2.x: nada del test apunta a una organización real."
  - q: "¿Se envía mi puntuación o lo que pulso a algún sitio?"
    a: "No. El test funciona por completo en tu navegador y no hace peticiones de red. No se guarda nada. Compartir es decisión tuya: el botón solo pasa la puntuación y la dirección del test al menú de compartir del móvil, o los copia."
  - q: "¿Cómo se eligen las preguntas?"
    a: "Cada partida elige al azar 10 de 32 escenarios, con tres o cuatro legítimos y al menos tres tipos distintos (correo, SMS, página de acceso, código QR, enlace). Si vuelves a jugar, tendrás una mezcla diferente."
  - q: "¿Qué son el smishing y el quishing?"
    a: "El smishing es phishing por SMS o mensajería. El quishing es phishing mediante un código QR: en una pegatina, un cartel o dentro de un correo. Un código QR oculta la dirección hasta que lo escaneas y te lleva al móvil, donde no puedes pasar el ratón sobre un enlace antes de abrirlo."
  - q: "¿Qué hago con un mensaje de phishing real?"
    a: "No pulses, no respondas ni abras adjuntos. Denúncialo — en el trabajo al equipo de IT o seguridad, y si no con la opción \"Denunciar phishing\" de tu proveedor de correo — y luego bórralo. Si ya escribiste una contraseña, cámbiala enseguida en la web real y activa la verificación en dos pasos."
  - q: "¿Puedo usarlo en formación de seguridad?"
    a: "Sí, es gratis y no necesita registro. Mira \"Úsalo para formar a tu equipo\" más abajo para hacerlo de forma sencilla en una reunión."
---

## Cómo funciona

Cada escenario es una simulación construida con elementos de página reales, no una imagen: se puede leer con un lector de pantalla y jugar solo con el teclado. Va acompañado de una línea de contexto ("Esperas una entrega…"), porque que un mensaje sea sospechoso depende a menudo de lo que estabas haciendo.

Los escenarios cubren los patrones de la mayoría del phishing:

- **Remitente y dominios parecidos** — `velorabank-alerts.test` en lugar de `velorabank.example`, un 1 en lugar de una l.
- **Adónde lleva de verdad un enlace** — el texto visible dice una cosa y el destino otra; un nombre conocido solo como subdominio del dominio de otro; el truco de la `@`.
- **Presión** — plazos, amenazas de suspensión, secretismo, "ahora no puedo hablar".
- **Peticiones que ningún servicio real hace** — el PIN de la tarjeta, tarjetas regalo, tasas para liberar un paquete.
- **Adjuntos y códigos QR** — tipos de archivo disfrazados, códigos QR que te llevan al móvil.

En el conjunto también hay mensajes legítimos, porque desconfiar de todo tiene un coste: avisos de seguridad reales, recibos y restablecimientos de contraseña que pediste tú. Después de responder, los elementos que deciden el caso se numeran sobre la simulación.

La página del resultado te da un nivel y enumera los temas detrás de tus errores, con enlaces a herramientas útiles: [Link Hazmat](../link-hazmat/) para revisar enlaces sospechosos y el analizador de cabeceras de correo para comprobar el remitente.

## Úsalo para formar a tu equipo

El test funciona bien como un bloque de 15 minutos en una reunión de equipo:

1. **Comparte pantalla** y abre esta página. Empieza el test.
2. **Lee cada escenario en voz alta** y da 30 segundos a la sala. Que la gente vote, a mano alzada o en el chat, antes de que nadie pulse.
3. **Responde lo que diga la mayoría** y repasad juntos las señales de alarma numeradas. Pregunta quién se había fijado en cada una.
4. **Después de la partida**, pide a todos que jueguen una vez por su cuenta y compartan su puntuación en el chat. El mensaje compartido solo lleva la puntuación y el enlace.
5. **Termina con vuestro procedimiento de aviso**: a quién decírselo, cómo, y qué pasa después de avisar.

Cada partida es distinta, así que las mismas personas pueden repetir en otra sesión. No se registra nada: el test es un ejercicio para aprender, no una evaluación de las personas.

## Casos de uso

- **Concienciación en seguridad** para equipos, colegios y familias, sin cuentas ni recogida de datos.
- **Incorporación de personal**: una introducción rápida y práctica a los mensajes que recibirá la gente nueva.
- **Autocomprobación** antes de abrir ese mensaje del banco o de la mensajería que no esperabas.
- **Docencia** sobre la diferencia entre un mensaje sospechoso y uno auténtico, usando las simulaciones para debatir.
