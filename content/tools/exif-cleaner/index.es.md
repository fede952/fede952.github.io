---
title: "Eliminar Datos EXIF y GPS de tus Fotos"
description: "Mira los metadatos EXIF ocultos de una foto (ubicación GPS, cámara, fecha) y descarga una copia limpia sin ellos. Funciona sin conexión en tu navegador."
intro: "**EXIF Cleaner** muestra los metadatos ocultos en una foto (coordenadas GPS, modelo de cámara, fecha de captura, software) y te da una copia limpia sin ninguno de ellos. La imagen nunca sale de tu dispositivo."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["eliminar datos exif", "borrar metadatos de fotos", "quitar gps de una foto", "quitar ubicación de imagen", "visor exif", "eliminar exif online", "metadatos de fotos", "limpiar metadatos"]
tags: ["privacidad", "osint", "imágenes", "herramienta"]
app_category: "SecurityApplication"
tool_file: "/tools/exif-cleaner/"
tool_title: "EXIF Cleaner: ver y eliminar metadatos"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Arrastra una foto a la zona de carga o haz clic para elegirla. JPEG funciona mejor; también se aceptan PNG y WebP."
  - "Lee la tabla **Metadatos Encontrados**: marca y modelo de cámara, fecha de captura, software, exposición, ISO, distancia focal, orientación, dimensiones, copyright, autor y coordenadas GPS."
  - "Si aparece un aviso rojo, la foto contiene una **ubicación GPS**. Las coordenadas decimales indican el lugar donde se tomó, con una precisión de pocos metros."
  - "Haz clic en **Eliminar Metadatos y Descargar**. La imagen se vuelve a dibujar sin ningún metadato y se guarda en el mismo formato."
  - "Haz clic en **Descargar Imagen Limpia** para guardar `tuarchivo-clean.jpg` (o .png/.webp) y comparte esa copia en lugar del original."
faq:
  - q: "¿Qué son los datos EXIF?"
    a: "EXIF (Exchangeable Image File Format) es un bloque de metadatos que cámaras y móviles escriben en cada foto: marca y modelo del dispositivo, objetivo, ajustes de exposición, fecha y hora, el software con que se editó y a menudo las coordenadas GPS del lugar de la toma. No se ve al mirar la imagen, pero se lee en segundos con herramientas como esta."
  - q: "¿Las redes sociales eliminan el EXIF automáticamente?"
    a: "Las grandes plataformas como Facebook, Instagram, X y WhatsApp quitan la mayor parte de los metadatos de las imágenes que publican. Los adjuntos de correo, los enlaces de almacenamiento en la nube, foros, webs de compraventa, apps de citas y muchas apps de mensajería al enviar \"como archivo\" o \"calidad original\" no lo hacen. Si tienes dudas, limpia antes la foto."
  - q: "¿Se sube mi foto para quitar los metadatos?"
    a: "No. La lectura de los metadatos y la creación de la copia limpia ocurren en JavaScript dentro de esta página. Puedes desconectarte de internet tras cargarla y la herramienta sigue funcionando, así que también sirve para fotos sensibles."
  - q: "¿La limpieza reduce la calidad de la imagen?"
    a: "La salida PNG es sin pérdida. JPEG y WebP se vuelven a codificar con calidad 95, prácticamente indistinguible del original en casi todas las fotos; el tamaño del archivo puede variar un poco. La resolución se mantiene exactamente igual."
  - q: "¿Por qué mi PNG o WebP no muestra metadatos?"
    a: "El visor usa exif-js, que lee el bloque EXIF de los archivos JPEG. PNG y WebP guardan los metadatos de otra forma y rara vez llevan GPS, así que la tabla puede quedar vacía. Aun así, la copia limpia se vuelve a codificar desde los píxeles, de modo que también se eliminan los metadatos que pudieran contener."
  - q: "¿La foto limpia seguirá viéndose derecha?"
    a: "Sí. Los móviles suelen guardar las fotos de lado y confían en la etiqueta EXIF Orientation para girarlas. El navegador aplica ese giro al dibujar la imagen, así que la copia limpia tiene la orientación correcta en sus propios píxeles y ya no necesita la etiqueta."
  - q: "¿Se pueden recuperar los metadatos eliminados de la copia limpia?"
    a: "No. El archivo limpio es una imagen nueva creada solo a partir de los píxeles; el bloque de metadatos original nunca se copia. Conserva el original si quieres la fecha y el lugar para tu archivo de fotos."
---

## Cómo funciona

### Lectura de los metadatos

Cuando sueltas un archivo, la página lo lee localmente con `FileReader` y se lo pasa a **exif-js** (v2.3.0, alojada aquí). La librería recorre el segmento APP1 del JPEG y decodifica los directorios EXIF con estructura TIFF: el directorio principal de la imagen (marca, modelo, software, orientación, copyright, autor), el subdirectorio Exif (tiempo de exposición, número f, ISO, distancia focal, flash, dimensiones en píxeles, espacio de color) y el directorio GPS.

Las coordenadas GPS se guardan en grados, minutos y segundos más una referencia de hemisferio (N/S, E/W). La herramienta las convierte a grados decimales, `grados + minutos/60 + segundos/3600`, en negativo para sur y oeste, y las muestra con seis decimales, unos 10 cm de precisión. Si hay una posición GPS, aparece el aviso rojo.

### Creación de la copia limpia

Los metadatos no se borran byte a byte: la herramienta descarta el contenedor entero.

1. El navegador decodifica la imagen en píxeles sin procesar.
2. Esos píxeles se dibujan a resolución completa en un `<canvas>` HTML. Al dibujarlos, el navegador aplica la orientación EXIF, así que el resultado queda derecho.
3. El canvas se codifica en un archivo totalmente nuevo con `canvas.toBlob()`: **JPEG con calidad 0,95** para los JPEG, **WebP con 0,95** para los WebP y **PNG** para todo lo demás.

Un canvas solo contiene píxeles, así que el archivo nuevo **no lleva EXIF, ni GPS, ni etiquetas XMP o IPTC, ni miniatura incrustada** (las miniaturas antiguas a veces muestran aún el original *sin recortar*) ni perfil de color. Las imágenes salen en sRGB, por lo que las fotos de gama amplia pueden verse muy ligeramente menos saturadas.

Puedes comprobar el resultado arrastrando de nuevo a la herramienta el archivo `-clean` descargado: la tabla estará vacía y no aparecerá el aviso de GPS.

### Lo que no toca

La copia limpia elimina los *metadatos*, no lo que se ve en la foto. Un letrero, un reflejo en un escaparate, una matrícula o un monumento reconocible pueden revelar igualmente dónde se tomó. Recorta o difumina esos detalles antes de compartirla.

## Casos de uso

- **Vender cosas por internet.** Las fotos de objetos hechas en casa pueden llevar las coordenadas GPS de tu vivienda. Límpialas antes de subirlas a una web de segunda mano.
- **Enviar fotos a personas que no conoces bien**, como un casero, una cita o un comprador, sin entregar tu dirección y tu modelo de móvil.
- **Periodismo y activismo.** Quita la ubicación y los datos del dispositivo de imágenes que podrían identificar a una fuente.
- **Revisar lo que vas a compartir.** Abre una foto y mira exactamente lo que revela; la primera vez que ves tu calle en un mapa impresiona.
- **Practicar OSINT.** Los investigadores usan el EXIF como pista. Usa el visor con imágenes de prueba para aprender qué se puede extraer y por qué importa limpiarlas.
