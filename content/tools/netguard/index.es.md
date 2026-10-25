---
title: "¿Cuál es mi IP? Test de Privacidad"
description: "Mira tu IP pública, proveedor y ubicación, comprueba la exposición de la IP local por WebRTC, la GPU y la huella del dispositivo, con nota de privacidad."
intro: "**NetGuard** muestra lo que cualquier web puede saber de ti en cuanto te conectas: tu dirección IP pública, tu proveedor y tu ubicación aproximada, además de las señales del dispositivo que el navegador entrega gratis. Un clic, una nota de privacidad y explicaciones claras."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["cuál es mi ip", "mi dirección ip", "test de fuga de ip", "test webrtc leak", "test de privacidad del navegador", "comprobar vpn", "qué saben las webs de mí", "nota de privacidad"]
tags: ["privacidad", "red", "vpn", "herramienta"]
app_category: "SecurityApplication"
tool_file: "/tools/netguard/"
tool_title: "NetGuard: test de privacidad del navegador y fugas de IP"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
howto:
  - "Pulsa **Run Privacy Scan**. El análisis dura unos cuatro segundos, casi todos para la comprobación WebRTC."
  - "Lee **Network & Location**: la IP pública, el proveedor y la ciudad que ve cualquier servidor web cuando te conectas, obtenidos a través de ipwho.is."
  - "Revisa la tarjeta **WebRTC**. Verde significa que el navegador no expuso ninguna dirección de red privada; en rojo aparecen las direcciones filtradas."
  - "Mira las tarjetas de huella (sistema operativo, navegador, pantalla, GPU, idioma y zona horaria, batería): cualquier web puede leerlas sin pedir permiso."
  - "Compara el **Privacy Score** antes y después de un cambio, por ejemplo al activar una VPN, cambiar de navegador o bloquear WebGL, y pulsa **Scan Again**."
faq:
  - q: "¿Cuál es mi dirección IP y quién puede verla?"
    a: "Tu IP pública es la dirección que tu proveedor (o tu VPN) asigna a la conexión. La ven todas las webs, servidores de anuncios y CDN que contactas, porque hace falta para devolverte la página. Suele revelar tu proveedor y tu ciudad o región, rara vez tu calle exacta."
  - q: "¿Una VPN oculta mi IP en este test?"
    a: "Sí: las tarjetas de IP, proveedor y ubicación mostrarán los datos del servidor VPN en lugar de los tuyos, que es justo para lo que sirve una VPN. La nota, en cambio, no sabe si una dirección es de una VPN y resta los mismos puntos por cualquier IP visible: compara las tarjetas, no solo el número."
  - q: "¿Qué es una fuga WebRTC?"
    a: "WebRTC permite a los navegadores crear conexiones entre pares para videollamadas. Para ello reúne \"candidatos ICE\", las direcciones de red donde se puede localizar tu dispositivo. Los navegadores antiguos exponían así a cualquier página la dirección LAN privada del dispositivo (como 192.168.1.23). NetGuard comprueba justo eso; los navegadores modernos ya la ocultan tras un nombre aleatorio `.local`."
  - q: "¿Puede NetGuard detectar si mi VPN filtra mi IP real por WebRTC?"
    a: "No del todo. La comprobación se hace sin servidor STUN, así que revela direcciones de red locales pero no pregunta a un servidor externo cómo se ve tu dirección pública a través de WebRTC. Para probar esa fuga concreta de las VPN, actívala, abre un test WebRTC específico basado en STUN y compara la dirección pública que indique con la IP que ves aquí."
  - q: "¿Por qué se ve el modelo de mi GPU?"
    a: "Con la extensión WebGL `WEBGL_debug_renderer_info` una página puede leer la cadena exacta del renderizador gráfico, por ejemplo un modelo de GPU de NVIDIA o Apple. Junto con el tamaño de pantalla, la zona horaria y el idioma, reduce las posibilidades a un grupo pequeño de dispositivos. Algunos navegadores devuelven un valor genérico o lo bloquean, y NetGuard lo marca como seguro."
  - q: "¿La herramienta guarda o envía mis datos?"
    a: "Solo sale una petición de tu navegador: la consulta a ipwho.is que devuelve tu IP pública y su ubicación, algo que cualquier web que visites podría hacer. Todo lo demás se lee y se muestra en local, y no se guarda nada al cerrar la página."
---

## Cómo funciona

El análisis ejecuta cinco comprobaciones seguidas, todas dentro de la página, y después las convierte en una nota.

**1. Identidad de red.** El navegador llama a `https://ipwho.is/`, una API pública de geolocalización por IP. La respuesta contiene la dirección desde la que salió la petición, el proveedor u organización a la que pertenece y el país, la ciudad y las coordenadas aproximadas de esa dirección. Es la misma información que cualquier servidor web obtiene de tu conexión, por eso la tarjeta aparece como aviso.

**2. Calidad de la conexión.** Donde existe la **Network Information API** (navegadores basados en Chromium), `navigator.connection` informa del ancho de banda estimado en Mbps, un tipo de conexión efectivo como `4g` y el tiempo de ida y vuelta. Firefox y Safari no la exponen, y la tarjeta lo indica.

**3. Huella del dispositivo.** NetGuard lee las señales que más recogen los scripts de fingerprinting:

- sistema operativo y versión del navegador, extraídos de la cadena `User-Agent`, además de `navigator.platform`;
- resolución de pantalla, relación de píxeles del dispositivo, tamaño de la ventana y profundidad de color;
- el **renderizador y fabricante de la GPU**, desde un contexto WebGL con la extensión `WEBGL_debug_renderer_info`;
- `navigator.language` y la zona horaria de `Intl.DateTimeFormat().resolvedOptions()`;
- nivel y estado de carga de la batería con `navigator.getBattery()`, donde el navegador aún lo implementa.

**4. Comprobación de direcciones locales por WebRTC.** La página crea una `RTCPeerConnection` sin servidores ICE, abre un canal de datos y genera una oferta. El navegador emite entonces candidatos ICE de tipo *host*, cada uno con una dirección de red. NetGuard recoge las direcciones IPv4 e ignora los nombres mDNS que terminan en `.local`, con los que los navegadores modernos ocultan la dirección LAN real. Toda dirección recogida aparece como expuesta. A los cuatro segundos la comprobación termina.

**5. Nota de privacidad.** La nota parte de 100 y pierde puntos por cada exposición encontrada:

| Señal | Puntos |
|---|---|
| IP pública y ubicación consultables | −30 |
| IP privada expuesta por WebRTC | −20 |
| Sistema, navegador y pantalla legibles | −10 |
| Modelo exacto de GPU legible | −10 |
| Idioma y zona horaria legibles | −5 |
| Estado de la batería legible | −5 |

Chrome en escritorio suele sacar un 40 (en nuestra prueba, exactamente eso); los navegadores que ocultan la cadena de la GPU o no implementan la Battery API sacan entre 5 y 15 puntos más. La cifra sirve para abrir la conversación, no es una medición de laboratorio: lo importante son las tarjetas.

## Casos de uso

- **Comprobar que la VPN está activa.** Conéctala y analiza: la IP, el proveedor y la ciudad deben ser los del proveedor de VPN, no los de tu conexión de casa.
- **Ver qué sabe una web antes de registrarte.** Las tarjetas son exactamente lo que un script de analítica o publicidad puede leer en la primera visita.
- **Comparar navegadores.** Haz el análisis en Chrome, Firefox, Brave y Safari: las tarjetas de GPU, batería y conexión cambian mucho entre ellos.
- **Entender un bloqueo geográfico.** Si una plataforma de streaming cree que estás en otro país, la tarjeta de ubicación muestra en qué país parece estar tu IP.
- **Explicar lo básico.** Una demo de dos minutos con NetGuard explica las direcciones IP, el fingerprinting y WebRTC mejor que una presentación. Para un análisis más profundo de la huella, prueba GhostPrint.
