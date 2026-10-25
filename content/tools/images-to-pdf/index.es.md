---
title: "JPG a PDF: convertir imágenes a PDF gratis"
description: "Junta imágenes JPG, PNG y WebP en un solo PDF en tu navegador: reordena, gira, elige A4, Carta o el tamaño de la imagen y márgenes. Sin subidas, sin EXIF."
intro: "Convierte fotos, escaneos y capturas en un solo **PDF**: suelta imágenes **JPG, PNG, WebP o GIF**, ordénalas, gira las que estén torcidas, elige **A4, Carta o el tamaño de la propia imagen** y un margen, y descarga. Las imágenes se procesan en esta pestaña y sus datos EXIF y GPS nunca acaban en el PDF."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["jpg a pdf", "convertir jpg a pdf", "imagen a pdf", "png a pdf", "fotos a pdf", "unir imágenes en pdf", "jpg a pdf sin subir", "webp a pdf"]
tags: ["pdf", "imágenes", "privacidad", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/images-to-pdf/"
tool_title: "Convertidor de imágenes a PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Suelta tus imágenes en el recuadro o haz clic para elegirlas. Cada imagen se convierte en una página; puedes añadir más en cualquier momento."
  - "Ordena las páginas arrastrando las miniaturas o con **←** y **→**. **⟳** gira una imagen 90° y **✕** la quita."
  - "Elige el **Tamaño de página**: **A4**, **Carta (US Letter)** o **Igual que la imagen** para páginas que coincidan exactamente con cada foto."
  - "Con A4 o Carta, la orientación **Automática (por imagen)** pone las imágenes anchas en páginas horizontales y las altas en verticales; puedes forzar **Vertical** u **Horizontal**. Elige un **Margen** (ninguno, 1 cm o 2 cm)."
  - "Pon el **Nombre del archivo** y pulsa **Crear PDF y descargar**."
faq:
  - q: "¿Se suben mis imágenes?"
    a: "No. El navegador decodifica las imágenes, las dibuja en un canvas y pdf-lib las coloca en un PDF, todo dentro de esta pestaña. No se envía nada a ningún servidor, algo importante para DNI, tiques e informes médicos."
  - q: "¿El PDF conserva la ubicación o los datos de cámara de mis fotos?"
    a: "No. Cada imagen se vuelve a dibujar en un canvas antes de insertarla, y un canvas no lleva metadatos, así que campos EXIF como la posición GPS, la fecha o el modelo de cámara no están en el PDF. El PDF solo recibe metadatos técnicos básicos de la biblioteca."
  - q: "¿Por qué mis fotos del móvil salen derechas?"
    a: "Los móviles suelen guardar las fotos de lado y anotan la rotación correcta en una etiqueta EXIF. La herramienta lee la imagen con esa orientación ya aplicada antes de dibujarla, así la página se ve como la foto de tu galería. Usa ⟳ si un escaneo sigue girado."
  - q: "¿Pierden calidad las imágenes?"
    a: "Las fotos se vuelven a codificar como JPEG de alta calidad (92%), visualmente idéntico para impresión y documentos. Las imágenes PNG, WebP y GIF se guardan sin pérdida como PNG, conservando textos nítidos y zonas transparentes."
  - q: "¿Cuánto ocupará el PDF?"
    a: "Más o menos lo mismo que las imágenes que añadas. Fotos muy grandes dan PDF grandes; si el archivo debe ser pequeño para un formulario, comprime antes las fotos, por ejemplo con un compresor de imágenes, y luego convierte."
  - q: "¿Puedo convertir fotos HEIC del iPhone?"
    a: "La mayoría de navegadores no leen HEIC directamente. Conviértelas antes a JPG con el convertidor HEIC de este sitio —también sin conexión en tu navegador— y luego añade aquí los JPG."
  - q: "¿Qué significa \"Igual que la imagen\"?"
    a: "La página tiene el tamaño de la foto a 96 píxeles por pulgada, más el margen. Es la mejor opción para capturas de pantalla y dibujos que no deben ajustarse a un formato de papel."
---

## Cómo funciona

### De la imagen a la página

Para cada imagen, la herramienta:

1. La decodifica con `createImageBitmap(file, { imageOrientation: 'from-image' })`, de modo que se respeta la orientación EXIF de las fotos del móvil.
2. La dibuja en un `<canvas>` aplicando tu rotación y la vuelve a codificar: como **JPEG al 92% de calidad** para fotos JPG, o como **PNG** para originales PNG, WebP y GIF, para conservar transparencias y bordes nítidos. De los GIF se usa el primer fotograma.
3. Inserta el resultado en el PDF con **pdf-lib** (`embedJpg` / `embedPng`).

### Maquetación

El A4 mide 595 × 842 puntos y el Carta 612 × 792 puntos (1 punto = 1/72 de pulgada). La imagen se escala para caber en la página menos el margen de cada lado, manteniendo sus proporciones, y se centra. Con la orientación automática, la página pasa a horizontal cuando la imagen es más ancha que alta. Con **Igual que la imagen**, cada página tiene el tamaño de la imagen a 96 PPP —una captura de 1920 × 1080 da una página de 1440 × 810 puntos— más el margen.

### Bibliotecas

pdf-lib (MIT) se carga desde este sitio solo cuando creas el PDF; la cuadrícula de miniaturas usa la decodificación de imágenes del propio navegador. No se pide nada a servidores de terceros.

## Casos de uso

- **Enviar escaneos de documentos en papel** —tiques, contratos, deberes— como un solo PDF que cualquier oficina pueda abrir.
- **Subir documentos de identidad o nóminas** a un formulario que solo acepta PDF, sin pasarlos antes por un convertidor online.
- **Crear un portafolio o un álbum** de JPG en el orden que elijas.
- **Archivar capturas** de una configuración, un error o una conversación en un único archivo fechado.
- **Preparar páginas listas para imprimir** en A4 o Carta con márgenes uniformes.
