---
title: "Generador de Códigos QR Gratis (PNG)"
description: "Crea códigos QR para enlaces o texto, elige colores y corrección de errores y descarga un PNG listo para imprimir. Códigos estáticos que nunca caducan."
intro: "Escribe un enlace o cualquier texto y obtén un **código QR estático** que puedes descargar como PNG nítido y listo para imprimir. El código se genera en tu navegador, contiene tus datos directamente y nunca caduca."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["generador de códigos qr", "crear código qr gratis", "código qr gratis", "código qr para enlace", "código qr png", "generador qr sin registro", "código qr estático", "código qr que no caduca"]
tags: ["código-qr", "utilidades", "herramienta"]
app_category: "UtilitiesApplication"
tool_file: "/tools/qr-generator/"
tool_title: "QuickLinker, generador de códigos QR"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Pega una URL (con `https://`) o escribe cualquier texto en el cuadro. También funcionan acentos, eñes, emoji y alfabetos no latinos."
  - "Si quieres, elige un color de **Primer Plano** y de **Fondo**. Mantén el primer plano claramente más oscuro que el fondo o muchas cámaras de móvil no lo leerán."
  - "Elige el nivel de **Corrección de Error**: **M (15%)** es el predeterminado; usa **Q** o **H** si el código va a imprimirse pequeño, en exteriores o con un logotipo encima."
  - "Pulsa **Generar QR** y comprueba la vista previa enfocando la pantalla con la cámara del móvil."
  - "Pulsa **Descargar .PNG** para guardar una imagen de unos 1200 px con el margen blanco necesario, lista para imprimir o para tus diapositivas."
faq:
  - q: "¿Caducan estos códigos QR?"
    a: "No. Son códigos QR estáticos: tu enlace o tu texto va codificado en el propio dibujo. No apuntan a ningún servidor nuestro, así que no hay nada que se pueda desactivar, ni suscripción, ni límite de escaneos. La contrapartida es que no puedes cambiar el destino después: si la URL cambia, genera un código nuevo."
  - q: "¿Este generador de códigos QR es realmente gratis?"
    a: "Sí, sin cuenta, sin marca de agua y sin límite de códigos. La página se financia con los anuncios que se muestran alrededor de la herramienta, no bloqueando funciones."
  - q: "¿Qué diferencia hay entre un QR estático y uno dinámico?"
    a: "Un QR dinámico contiene un enlace corto al servidor del proveedor, que redirige a tu URL real. Así el proveedor puede contar escaneos y cambiar el destino, pero el código deja de funcionar si dejas de pagar o el servicio cierra, y cada escaneo pasa por sus servidores. Un código estático, como los de aquí, va directo a tu URL."
  - q: "¿Qué nivel de corrección de errores elijo?"
    a: "L recupera alrededor del 7 % de los módulos dañados, M el 15 %, Q el 25 % y H el 30 %. Los niveles altos hacen el código más denso con el mismo contenido. M es adecuado para pantallas e impresiones limpias; elige Q o H para pegatinas pequeñas, superficies rugosas o si vas a poner un logotipo en el centro."
  - q: "¿Cuánto texto cabe en un código QR?"
    a: "El generador elige automáticamente la más pequeña de las 40 versiones QR en la que cabe el contenido. Con el nivel M, un código versión 40 admite unos 2.300 bytes de texto, pero códigos tan grandes cuestan de leer con el móvil. Para enlaces, cuanto más corto mejor: una URL de 30–60 caracteres da un código limpio y fácil de escanear."
  - q: "¿Por qué no se lee mi código QR de colores?"
    a: "Los lectores buscan módulos oscuros sobre fondo claro con suficiente contraste. Los colores invertidos (claro sobre oscuro), combinaciones con poco contraste como amarillo sobre blanco o una imagen detrás del código son las causas habituales. Negro o un color oscuro sobre blanco es lo más seguro."
  - q: "¿Se envía a algún sitio lo que escribo?"
    a: "No. El código QR lo calcula una librería JavaScript que se ejecuta en esta página y se dibuja en un canvas. No se sube nada, algo importante si codificas una contraseña de Wi-Fi, una URL interna o una nota privada."
---

## Cómo funciona

La herramienta usa la librería de código abierto **qrcode-generator** de Kazuhiko Arase (v1.4.4, alojada en este sitio) y dibuja el resultado en un canvas HTML.

1. **Codificación.** Tu texto se convierte a bytes en **UTF-8** y se guarda en *modo byte*, así que `é`, `ñ`, `ç`, `€` y los emoji salen exactamente como los escribiste cuando un móvil los lee. (Por defecto la librería guardaría un solo byte por carácter y estropearía todo lo que no sea latín básico, por eso la página la cambia a UTF-8 de forma explícita.)
2. **Elección de versión.** La librería elige la **versión QR** más pequeña, desde la 1 (21 × 21 módulos) hasta la 40 (177 × 177), capaz de contener tus datos con el nivel de corrección elegido.
3. **Corrección de errores.** Los códigos QR añaden palabras de corrección **Reed–Solomon** para que un lector pueda reconstruir partes que falten o estén sucias: el nivel **L** recupera ~7 %, **M** ~15 %, **Q** ~25 % y **H** ~30 % de las palabras de código.
4. **Dibujo.** Cada módulo oscuro se dibuja como un cuadrado del color de primer plano. Alrededor del símbolo la herramienta deja una **zona de silencio de 4 módulos** del color de fondo, el margen que exige el estándar QR (ISO/IEC 18004); sin él, los lectores fallan en cuanto el código está sobre una página de color.
5. **Exportación.** La vista previa en pantalla mide unos 300 px. Al descargar, el código se vuelve a dibujar a unos **1200 px**, con cada módulo de un número entero de píxeles para que los bordes queden nítidos, y se guarda como `qrcode.png`.

| Contenido | Longitud típica | Versión con nivel M | Módulos |
|---|---|---|---|
| URL corta | 25 caracteres | 2 | 25 × 25 |
| URL normal con ruta | 60 caracteres | 4 | 33 × 33 |
| URL larga con parámetros de seguimiento | 150 caracteres | 8 | 49 × 49 |
| Un párrafo de texto | 500 caracteres | 17 | 85 × 85 |

Cuantos menos módulos, más grande es cada uno al imprimirlo y más fácil es leer el código a distancia; por eso quitar los parámetros de seguimiento de una URL suele importar más que el nivel de corrección.

## Casos de uso

- **Impresión y envases.** Pon un código QR en folletos, tarjetas de visita, cartas de restaurante o etiquetas que abra tu web, una página de reseñas o un manual. Un código estático funciona mientras funcione la URL.
- **Presentaciones y pósteres.** Deja que el público abra tus diapositivas, una encuesta o un repositorio sin teclear una dirección larga.
- **Compartir texto sin conexión.** Codifica una nota breve, un número de serie o datos de contacto que un móvil puede leer sin red.
- **Probar tus propias apps.** Genera códigos para deep links, URLs de staging o pruebas de callbacks OAuth sin pegar direcciones internas en un servicio de terceros.
- **Concienciación en seguridad.** El "quishing" (phishing con QR) esconde enlaces maliciosos tras un código. Generar los tuyos te permite enseñar a tus compañeros lo fácil que es que un código apunte a cualquier sitio, y por qué conviene mirar la URL que muestra el móvil antes de tocar.
