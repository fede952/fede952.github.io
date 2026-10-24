---
title: "Comprimir Imágenes Online: JPG, PNG, WebP"
description: "Reduce el peso de imágenes JPG, PNG y WebP en tu navegador: calidad, tamaño objetivo y ancho máximo, conversión a WebP. Sin subir archivos ni registrarte."
intro: "**PixelShrink** comprime y convierte imágenes en tu propio dispositivo. Arrastra una foto, elige la calidad, un tamaño objetivo o un ancho máximo y descarga un JPG, PNG o WebP más ligero. La imagen nunca se sube."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["comprimir imágenes", "reducir peso de imagen", "compresor de imágenes online", "comprimir jpg", "comprimir png", "convertir a webp", "redimensionar imagen", "comprimir foto sin subirla"]
tags: ["imágenes", "compresión", "privacidad", "herramienta"]
app_category: "MultimediaApplication"
tool_file: "/tools/pixel-shrink/"
tool_title: "PixelShrink, compresor de imágenes"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Arrastra una imagen a la zona de carga o haz clic para elegir un archivo. Se aceptan PNG, JPEG, WebP y AVIF; la vista previa muestra el peso y las dimensiones."
  - "Elige el **formato de salida**: mantener el original o convertir a JPEG, PNG o WebP. Para fotos, WebP suele ser el más ligero."
  - "Ajusta la **calidad** (1–100, 75 por defecto), un **tamaño máximo** en MB y un **ancho máximo** en píxeles: el lado más largo se reduce a ese valor manteniendo la proporción."
  - "Haz clic en **Comprimir Imagen**. El panel antes/después muestra ambos pesos, ambas dimensiones y el porcentaje ahorrado."
  - "Haz clic en **Descargar Imagen Comprimida** para guardar el resultado. Si no es más pequeño que el original, la herramienta te avisa: conserva el original o prueba otro formato."
faq:
  - q: "¿Mis imágenes se suben a un servidor?"
    a: "No. La imagen se decodifica, redimensiona y vuelve a codificar dentro de tu navegador, en un Web Worker en segundo plano. No se envía nada: una vez cargada la página puedes quedarte sin conexión y sigue funcionando. Por eso también es seguro para capturas de documentos, DNI o cualquier cosa privada."
  - q: "¿Qué calidad debo usar?"
    a: "Para fotos, 70–80 es el punto ideal: el archivo se reduce mucho y a tamaño normal cuesta ver diferencias. Baja a 50–60 para miniaturas o vistas previas. Por encima de 90 el archivo crece rápido sin ganancia visible."
  - q: "¿Conviene convertir a WebP?"
    a: "Para la web, normalmente sí. Los archivos WebP suelen ser un 25–35 % más ligeros que un JPEG de calidad similar y todos los navegadores actuales los muestran. Mantén JPEG cuando la imagen vaya a un sistema que solo acepta JPG, como algunos formularios o servicios de impresión."
  - q: "¿Por qué mi PNG ha aumentado de tamaño?"
    a: "PNG es un formato sin pérdida, así que una fotografía guardada en PNG suele pesar más que el JPEG original. PixelShrink reduce los PNG limitando la paleta de colores, lo que funciona muy bien con capturas, logotipos y gráficos planos y mal con fotos. Para fotos, elige WebP o JPEG."
  - q: "¿Puedo comprimir una imagen por debajo de un tamaño exacto, como 200 KB?"
    a: "Pon **Tamaño máximo** en 0,2 MB. Si la primera codificación es mayor, la librería la repite hasta 10 veces bajando un poco la calidad y las dimensiones en cada pasada, y se detiene en cuanto el archivo cabe. Con imágenes muy grandes o detalladas puede hacer falta también un ancho máximo menor."
  - q: "¿La compresión elimina los datos EXIF y la ubicación GPS?"
    a: "Sí. La imagen se vuelve a dibujar en un canvas y se codifica de nuevo sin copiar los metadatos, así que desaparecen campos EXIF como el modelo de cámara, la fecha y las coordenadas GPS. Si solo quieres quitar los metadatos sin recomprimir, usa EXIF Cleaner."
  - q: "¿Por qué no hay salida en AVIF?"
    a: "La salida la produce el codificador de imágenes del propio navegador, y la mayoría de navegadores puede mostrar AVIF pero no crearlo desde un canvas. PixelShrink lo comprueba al cargar y solo muestra la opción AVIF si tu navegador puede codificarlo de verdad, en lugar de generar a escondidas un PNG con extensión .avif."
---

## Cómo funciona

PixelShrink es una interfaz ligera sobre [browser-image-compression](https://github.com/Donaldcwl/browser-image-compression) (v2.0.2, alojada en este sitio). Al pulsar Comprimir, el trabajo pasa a un **Web Worker**, de modo que la página sigue respondiendo incluso con una foto de 20 megapíxeles.

1. **Decodificar.** El archivo se decodifica a un mapa de bits con `createImageBitmap` (o con un elemento `<img>` como alternativa) y se aplica la orientación EXIF para que las fotos verticales no salgan giradas.
2. **Redimensionar.** Si el lado más largo supera el *ancho máximo*, la imagen se dibuja en un canvas más pequeño con la misma proporción. Una foto de 6000 × 4000 con límite de 2048 px queda en 2048 × 1365.
3. **Codificar.** JPEG y WebP los codifica el navegador (`canvas.toBlob` / `OffscreenCanvas.convertToBlob`) con tu ajuste de calidad. El PNG pasa por **UPNG.js**, que cuantiza la imagen a una paleta de como máximo 4096 × calidad colores (3.072 colores con el 75 por defecto) antes de escribir un PNG sin pérdida: es el truco que reduce a la mitad o más las capturas y los gráficos de interfaz.
4. **Ajustarse al tamaño.** Si el resultado sigue superando el *tamaño máximo*, la codificación se repite hasta **10 veces**. En cada pasada la calidad se multiplica por 0,95 (0,85 para PNG) y las dimensiones pueden escalarse por 0,95, hasta que el archivo cabe o se acaban las pasadas.

El panel antes/después compara el archivo original con el resultado, y la descarga es una URL local `blob:` con el nombre `tuarchivo-compressed.<formato>`. Como la imagen se vuelve a codificar desde los píxeles, **los metadatos como EXIF y GPS no se conservan**.

### Qué formato elegir

| Contenido | Mejor formato | Por qué |
|---|---|---|
| Fotos para una web o un blog | WebP, calidad 70–80 | Archivos más ligeros, compatibles con todos los navegadores |
| Fotos para correo, formularios, impresión | JPEG, calidad 75–85 | Se acepta en todas partes |
| Capturas, diagramas, logotipos | PNG o WebP | Los bordes nítidos y colores planos se comprimen bien |
| Imágenes con transparencia | PNG o WebP | JPEG no tiene canal alfa |

**AVIF** solo aparece cuando el navegador puede *codificarlo* de verdad desde un canvas. Hoy la mayoría no puede, y PixelShrink lo comprueba al cargar en lugar de adivinar.

## Casos de uso

- **Páginas web más rápidas.** Las imágenes de cabecera demasiado grandes son la causa más común de un mal Largest Contentful Paint. Convertir un JPEG de 3 MB en un WebP de 2000 px con calidad 75 suele dejarlo por debajo de 300 KB.
- **Límites de subida.** Sedes electrónicas, portales de empleo y tickets de soporte suelen limitar los adjuntos a 1 o 2 MB. Fija el tamaño máximo y deja que la herramienta encuentre la calidad que cabe.
- **Correo y chat.** Envía cinco fotos de las vacaciones en lugar de una cuando cada una pesa la décima parte.
- **Documentos privados.** Reduce el escaneo de un DNI o de un contrato sin entregárselo a un servicio online del que no sabes nada.
- **Recursos para apps y juegos.** Convierte sprites PNG o capturas en archivos más ligeros antes de subirlos a un repositorio.
