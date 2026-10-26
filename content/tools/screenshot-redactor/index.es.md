---
title: "Ocultar datos en una captura de pantalla"
description: "Tapa correos, nombres, IBAN y otras partes sensibles de una captura. Cajas sólidas fundidas en los píxeles, metadatos eliminados, todo en tu navegador."
intro: "Pega una captura (Ctrl+V), arrastra una imagen o elígela y luego **arrastra para tapar** lo sensible: correos, nombres, números de cuenta, caras, URL. Lo tapado son **cajas sólidas fundidas en los píxeles** — sin capas que quitar — y el PNG o JPEG exportado **no lleva metadatos**. Una ayuda opcional puede **sugerir cajas** sobre correos, IBAN, números de tarjeta y teléfono y direcciones IP. No se sube nada."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["ocultar datos en captura de pantalla", "tapar texto en imagen", "censurar captura de pantalla", "ocultar información sensible imagen", "difuminar imagen online", "pixelar imagen online", "borrar datos personales de una captura", "tachar texto en imagen"]
tags: ["privacidad", "imágenes", "seguridad", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/screenshot-redactor/"
tool_title: "Ocultador de capturas"
tool_height: 1050
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write; clipboard-read"
howto:
  - "Pega una captura con **Ctrl+V** (⌘V en Mac), arrastra una imagen al recuadro o pulsa **Elegir una imagen**."
  - "Deja seleccionada **Caja sólida** (negra por defecto; elige otro **Color** si quieres) y arrastra sobre cada zona que ocultar. En el móvil, arrastra con un dedo y usa **Mover** para desplazarte por una imagen ampliada."
  - "Opcional: pulsa **Sugerir zonas** para encontrar correos, IBAN, números de tarjeta, teléfonos y direcciones IP con reconocimiento de texto en tu dispositivo. Desmarca las sugerencias que quieras dejar a la vista y **tapa** el resto."
  - "Usa **Deshacer** / **Rehacer** (Ctrl+Z / Ctrl+Y) y los botones de zoom para revisar los bordes de cada caja."
  - "Elige **PNG** (texto nítido) o **JPEG** (fotos más ligeras) y pulsa **Descargar la imagen ocultada**, o **Copiar imagen** para pegarla directamente en un chat o un ticket."
faq:
  - q: "¿Se sube mi imagen a algún sitio?"
    a: "No. La imagen se decodifica, se edita y se exporta dentro de tu navegador. El reconocimiento de texto opcional también se hace en tu dispositivo; la primera vez descarga sus archivos (unos 10 MB) desde esta web, nunca de terceros, y la imagen no se envía a ningún sitio."
  - q: "¿Por qué una caja sólida es más segura que el desenfoque o el pixelado?"
    a: "Una caja sólida sustituye los píxeles por un solo color: no queda nada del original. El desenfoque y el pixelado conservan una versión reducida de los píxeles originales. Con textos cortos o previsibles — números, cifras de una tarjeta, nombres en una fuente conocida — a veces basta para reconstruirlos o adivinarlos, por ejemplo desenfocando o pixelando de la misma forma textos candidatos y comparando el resultado. Úsalos solo para lo que simplemente deba destacar menos."
  - q: "¿Se puede quitar lo tapado del archivo descargado?"
    a: "No. La exportación es una imagen nueva dibujada a partir de los píxeles editados: sin capas, sin original oculto y sin historial de edición en el archivo. Esa es la diferencia con tapar texto con una forma en un documento o un PDF, donde a menudo el texto de debajo aún se puede seleccionar."
  - q: "¿Elimina los datos EXIF y GPS?"
    a: "Sí. El PNG o JPEG exportado lo codifica de cero el navegador y no contiene metadatos: ni modelo de cámara, ni fecha, ni posición GPS. La orientación de la foto se aplica antes a los píxeles, así que la imagen se ve en la posición correcta."
  - q: "¿Qué encuentra la sugerencia automática?"
    a: "Direcciones de correo, IBAN (comprobados con su control mod 97), números de tarjeta (comprobados con el algoritmo de Luhn), teléfonos y direcciones IPv4 e IPv6. Funciona con texto de pantalla en alfabeto latino. No detecta nombres, caras, direcciones postales ni escritura a mano, así que revisa siempre tú la imagen antes de compartirla."
  - q: "¿Qué formatos de imagen puedo abrir?"
    a: "Cualquiera que tu navegador pueda mostrar: PNG, JPEG, WebP, GIF (primer fotograma) y normalmente AVIF y BMP. Las fotos HEIC del iPhone hay que convertirlas antes, por ejemplo con el conversor HEIC de esta web."
---

## Cómo funciona

### Lo tapado son píxeles, no capas

La imagen se decodifica en un canvas a resolución completa, aplicando la orientación EXIF de la foto. Cada caja que dibujas se guarda como un rectángulo, y la composición de imagen más cajas se reconstruye a partir de los píxeles originales cada vez que dibujas, deshaces o rehaces. Al exportar, esa composición se codifica en un PNG o JPEG totalmente nuevo. El archivo solo contiene los píxeles finales: lo que había bajo una caja ya no existe en él.

Por eso fallan tan a menudo las ocultaciones hechas en editores de documentos: un rectángulo negro dibujado sobre un texto en un documento o un PDF es un objeto aparte, y el texto de debajo todavía se puede seleccionar o extraer. Aquí no hay nada debajo.

### Por qué el desenfoque y el pixelado llevan un aviso

El pixelado sustituye cada bloque de píxeles por su color medio; el desenfoque reparte cada píxel entre sus vecinos. Los dos tiran información, pero no toda. En un texto, la forma de cada letra sigue influyendo en el resultado, y los posibles originales suelen ser pocos: un número de tarjeta solo tiene diez cifras posibles por posición y las capturas usan un puñado de fuentes conocidas. Se pueden escribir textos candidatos en la misma fuente, pixelarlos o desenfocarlos igual y quedarse con el que coincide. Herramientas públicas e investigaciones han demostrado que funciona con contraseñas y números pixelados. Una caja sólida no deja nada que comparar, por eso es el modo predeterminado y el único recomendado para lo secreto.

### Las sugerencias opcionales

El reconocimiento de texto usa Tesseract, un motor OCR de código abierto compilado a WebAssembly y servido desde esta web. Solo se carga cuando pulsas **Sugerir zonas**. Las palabras reconocidas se comparan con patrones de correos, IBAN, números de tarjeta, teléfonos y direcciones IP; los IBAN y las tarjetas además deben pasar su dígito de control, lo que reduce las falsas alarmas. Cada coincidencia se convierte en una caja discontinua que puedes aceptar o descartar.

## Casos de uso

- **Informes de errores y tickets de soporte** — comparte la captura de un error sin tu correo, el ID de cuenta o una clave de API.
- **Redes sociales y foros** — publica una conversación o un recibo con los nombres, teléfonos y números de pedido tapados.
- **Documentación y tutoriales** — oculta URL internas, direcciones IP y datos de clientes en capturas de paneles de administración.
- **Notas de gastos** — envía la foto de un tique o de una transferencia con el número de cuenta tapado.
- **Trabajo de seguridad** — incluye pruebas en un informe sin filtrar las credenciales o los datos personales que contienen.
