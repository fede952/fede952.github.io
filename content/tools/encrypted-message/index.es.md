---
title: "Mensaje cifrado con contraseña en un enlace"
description: "Cifra un mensaje en tu navegador con AES-256 y una frase de contraseña y compártelo como enlace. El texto nunca se sube: solo existe dentro del enlace."
intro: "Escribe un mensaje, elige una frase de contraseña y obtén un **enlace** que contiene el mensaje **cifrado con AES-256-GCM**. Envía el enlace y la frase **por canales distintos**; quien lo recibe abre el enlace y lo descifra en su navegador. No se sube ni se guarda nada: el texto cifrado viaja dentro del propio enlace, en la parte tras `#` que los navegadores nunca envían a un servidor."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["enlace mensaje cifrado", "enviar mensaje cifrado", "cifrar texto online", "mensaje protegido con contraseña", "compartir contraseña de forma segura", "enviar nota secreta", "encriptar mensaje con contraseña", "enlace mensaje privado"]
tags: ["security", "privacy", "encryption", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/encrypted-message/"
tool_title: "Enlace con mensaje cifrado"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Escribe el **mensaje**: una contraseña del wifi, un código de portal, una nota privada corta."
  - "Escribe una **frase de contraseña** de al menos 8 caracteres, o pulsa **Generar** para obtener una aleatoria."
  - "Pulsa **Crear enlace cifrado** y **Copiar enlace**."
  - "Envía el enlace por un canal (por ejemplo, el correo) y la **frase por otro** (una llamada, otra app de mensajería). Nunca los dos en el mismo mensaje."
  - "Quien lo recibe abre el enlace, escribe la frase y lee el mensaje en su propio navegador."
faq:
  - q: "¿Se sube mi mensaje a algún sitio?"
    a: "No. El cifrado se hace en tu navegador con la Web Crypto API. El mensaje cifrado va en el enlace después del signo #, y los navegadores no envían esa parte al servidor cuando se abre el enlace. Este sitio nunca recibe el mensaje, la frase ni el fragmento del enlace, así que no hay nada guardado que pueda filtrarse o borrarse."
  - q: "¿El enlace se autodestruye tras leerlo?"
    a: "No, y ninguna herramienta sin servidor puede prometerlo. El enlace es el mensaje cifrado, así que funciona mientras alguien tenga una copia: en un buzón, un historial de chat o una copia de seguridad. Trátalo como el propio secreto: quien tenga el enlace y la frase puede leerlo. Si necesitas un mensaje que desaparezca, usa un servicio que lo guarde en un servidor y lo borre tras la lectura, y asume que confías en ese servidor."
  - q: "¿Qué tan fuerte es el cifrado?"
    a: "El mensaje se cifra con AES-256 en modo GCM, que además detecta cualquier cambio en el enlace. La clave se deriva de tu frase con PBKDF2-HMAC-SHA-256 y 600 000 iteraciones, con sal e IV aleatorios en cada mensaje. El punto débil es la frase: una corta o fácil de adivinar puede romperse por fuerza bruta por quien tenga el enlace, así que usa una larga o el botón Generar."
  - q: "¿Y si la frase es incorrecta o el enlace está cortado?"
    a: "El descifrado falla con un mensaje claro. El cifrado autenticado no distingue una frase incorrecta de un enlace modificado, así que revisa ambos. Algunas apps cortan los enlaces muy largos: la herramienta avisa por encima de unos 2000 caracteres."
  - q: "¿Por qué enviar la frase por separado?"
    a: "Porque el enlace solo no sirve sin ella. Si viajan juntos en el mismo correo o chat, cualquiera que pueda leer esa conversación, ahora o más adelante, por ejemplo tras el robo de una cuenta, puede leer también el mensaje."
  - q: "¿Puedo ver qué hace la herramienta?"
    a: "Sí. El código se ejecuta en tu navegador y se puede leer con las herramientas para desarrolladores. En la pestaña Red también puedes comprobar que crear y abrir un enlace no envía ninguna petición con tu mensaje."
---

## Cómo funciona

### Cifrado en tu navegador

Al pulsar **Crear enlace cifrado**, la página genera una sal aleatoria de 16 bytes y un IV aleatorio de 12 bytes, deriva de tu frase una clave de 256 bits con **PBKDF2-HMAC-SHA-256** (600 000 iteraciones) y cifra el mensaje con **AES-256-GCM**. La sal, el IV y el texto cifrado con su etiqueta de autenticación se unen, se codifican en Base64url y se colocan tras `#v1.` en el enlace.

### Por qué el mensaje nunca llega a un servidor

La parte de una URL tras `#` es el **fragmento**. Los navegadores la mantienen en el dispositivo: no se envía en la petición de la página ni se incluye en la cabecera `Referer`. El enlace abre una página mínima de este sitio, sin publicidad ni estadísticas, que lee el fragmento, lo quita de la barra de direcciones y pide la frase. El descifrado ocurre en el dispositivo de quien recibe.

### De qué no protege

- **De quien tenga el enlace y la frase** — así lo lee el destinatario, y así podría leerlo cualquier otra persona.
- **De una frase débil** — quien tenga el enlace puede probar frases sin conexión tan rápido como permita su hardware; las 600 000 iteraciones hacen cada intento lento, no imposible.
- **De un dispositivo comprometido** — un malware en el dispositivo de quien envía o recibe puede leer el mensaje antes de cifrarlo o después de descifrarlo.
- **De las copias del enlace** — buzones, historiales de chat y copias de seguridad lo conservan. No hay forma de revocarlo.

## Casos de uso

- **Compartir una contraseña o la clave del wifi** con un compañero o un invitado sin dejarla legible en el historial del chat.
- **Enviar el código del portal o el PIN de la alarma** a un repartidor o a quien cuida la casa.
- **Pasar un código de recuperación o una clave de API** a un compañero por correo, con la frase dicha por teléfono.
- **Dejar una nota privada** en un sitio público — un ticket, un foro, un documento compartido — que solo pueda leer quien tenga la frase.
- **Antes de enviar**, comprueba lo difícil que es adivinar tu frase de contraseña con [PassFort](../pass-fort/).
