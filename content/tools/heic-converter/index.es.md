---
title: "Convertir HEIC a JPG sin subir fotos"
description: "Convierte fotos HEIC del iPhone a JPG o PNG en tu navegador: por lotes, con calidad ajustable, eliminación opcional de EXIF/GPS y descarga ZIP. Sin subidas."
intro: "Convierte tus **fotos HEIC del iPhone a JPG o PNG** sin subirlas a ningún sitio: suelta uno o cien archivos, elige formato y calidad, decide si eliminar los metadatos EXIF y la ubicación GPS, y descarga cada archivo o un único ZIP. El decodificador funciona dentro de esta pestaña del navegador."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["convertir heic a jpg", "heic a jpg", "convertidor heic", "heic a png", "foto iphone a jpg", "abrir archivo heic", "convertir heic online", "heic a jpg gratis"]
tags: ["imágenes", "privacidad", "convertidor", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/heic-converter/"
tool_title: "Convertidor de HEIC a JPG y PNG"
tool_height: 720
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Suelta tus fotos `.heic` o `.heif` en el recuadro o haz clic para elegirlas. Puedes añadir varias a la vez y más después."
  - "La primera vez, la página carga su decodificador HEIC (unos 1,5 MB, una vez por visita). Después cada foto se decodifica y convierte por turno; junto al nombre aparecen una miniatura y el nuevo tamaño."
  - "Elige **JPG** (archivos más ligeros, **Calidad JPG** ajustable) o **PNG** (sin pérdida, más pesado). Al cambiar una opción se vuelven a convertir las fotos de la lista."
  - "Deja marcada **Eliminar metadatos (EXIF, ubicación GPS)** para obtener archivos limpios, o desmárcala para conservar en el JPG los datos de la cámara y la ubicación."
  - "Pulsa **Descargar** en una foto, o **Descargar todo (.zip)** para guardar todos los archivos convertidos en un solo archivo."
faq:
  - q: "¿Se suben mis fotos a un servidor?"
    a: "No. Los archivos se leen con la File API del navegador y los decodifica una versión WebAssembly de libheif que se ejecuta en esta pestaña. Las únicas peticiones de red son para descargar el decodificador; tus fotos nunca salen del dispositivo. Puedes comprobarlo en el panel Red del navegador mientras conviertes."
  - q: "¿Por qué el iPhone guarda las fotos en HEIC?"
    a: "HEIC guarda una imagen comprimida con HEVC (H.265) dentro de un contenedor HEIF. Con una calidad similar, los archivos ocupan más o menos la mitad que un JPEG, por eso iOS lo usa por defecto. Muchas aplicaciones de Windows, webs y dispositivos antiguos todavía no lo abren, de ahí la necesidad de convertir."
  - q: "¿Perderé calidad?"
    a: "Convertir a JPEG vuelve a comprimir la imagen. Con la calidad predeterminada de 85 la diferencia es muy difícil de ver y el archivo sigue siendo ligero; usa 95–100 si vas a editar la foto. PNG no tiene pérdida, pero suele ocupar de tres a cinco veces más que el HEIC original."
  - q: "¿Qué elimina \"Eliminar metadatos\"?"
    a: "Todo salvo los píxeles: los datos EXIF de la cámara, la fecha y la hora y, sobre todo, la posición GPS, que puede revelar dónde vives o trabajas. Con la opción desactivada, el convertidor copia en el JPEG el bloque EXIF original y restablece la etiqueta de orientación, porque el decodificador ya ha girado la imagen."
  - q: "Mi HEIC tiene varias imágenes (Live Photo, ráfaga). ¿Cuál se convierte?"
    a: "La imagen principal, la que muestra la app Fotos. La parte en movimiento de una Live Photo es un archivo de vídeo aparte y no se incluye."
  - q: "¿Hay un límite de tamaño o de número?"
    a: "Solo la memoria de tu dispositivo. Cada foto se decodifica en píxeles sin comprimir (una foto de 12 megapíxeles ocupa unos 48 MB mientras se convierte), así que los lotes muy grandes van más rápido en un ordenador que en un móvil antiguo."
  - q: "¿Puedo convertir HEIC a PNG con transparencia?"
    a: "Las fotos de las cámaras de los móviles no tienen transparencia. Si una imagen HEIF tiene canal alfa, el PNG lo conserva; el JPEG no admite transparencia y la rellena de negro."
---

## Cómo funciona

### Decodificar sin servidor

Los navegadores distintos de Safari no pueden abrir HEIC por sí solos, porque el formato envuelve imágenes comprimidas en **HEVC** dentro de un contenedor **HEIF** (ISO/IEC 23008-12). Esta página incluye **libheif** —la biblioteca de referencia de código abierto para HEIF, compilada a WebAssembly por el proyecto libheif-js— y la carga solo cuando sueltas el primer archivo, para que la página siga siendo ligera.

Para cada archivo, el convertidor:

1. Lee los bytes con la File API y comprueba en la caja `ftyp` que la marca sea HEIF (`heic`, `heix`, `mif1`…), así un JPEG renombrado se notifica en lugar de bloquear el decodificador.
2. Decodifica la imagen principal con libheif en un mapa de bits RGBA. La rotación y el reflejo guardados en el archivo (`irot`, `imir`) se aplican en este paso.
3. Dibuja el mapa de bits en un `<canvas>` y lo codifica con `canvas.toBlob()` como JPEG con la calidad elegida o como PNG.

### Metadatos

Un canvas nunca lleva metadatos, así que el archivo convertido sale limpio por defecto. Si eliges conservarlos, el convertidor analiza él mismo el contenedor HEIF —la caja `meta`, la lista de elementos (`iinf`) y sus ubicaciones (`iloc`)— para encontrar el elemento de tipo `Exif` e insertarlo en el JPEG como segmento **APP1** estándar. En la copia, la etiqueta `Orientation` se pone a 1 (normal); de lo contrario, los visores girarían una foto que ya está derecha. La salida PNG se escribe siempre sin metadatos.

### Descarga en ZIP

Con más de un archivo, **Descargar todo** carga una pequeña biblioteca ZIP (JSZip), añade cada archivo convertido y guarda un único archivo comprimido. Los nombres repetidos reciben un sufijo numérico (`IMG_0001-2.jpg`).

## Casos de uso

- **Enviar fotos del iPhone a usuarios de Windows o a formularios** que solo aceptan JPG o PNG: candidaturas, partes de seguros, sedes electrónicas.
- **Publicar en la web sin revelar tu ubicación.** Convierte y elimina el EXIF en un solo paso antes de subir a un marketplace o foro.
- **Archivar.** Convierte a JPG una carpeta de fotos de vacaciones para el portátil antiguo de un familiar o un marco digital.
- **Diseñadores y desarrolladores** que reciben capturas o maquetas en HEIC y necesitan PNG para la documentación.
- **Imágenes sensibles** —documentos, DNI, fotos médicas— que no deberían pasar por un convertidor online que no puedes comprobar.
