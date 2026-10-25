---
title: "Ocultar Texto en una Imagen (LSB)"
description: "Oculta un mensaje secreto dentro de una imagen con esteganografía LSB y revélalo después. Exporta un PNG sin pérdida; todo en tu navegador, sin subidas."
intro: "**Steganography Lab** oculta un mensaje de texto en los píxeles de una imagen y lo vuelve a leer después. La foto parece idéntica, porque cada valor de color cambia como mucho 1 de 255. Todo ocurre en tu navegador: la imagen y el mensaje nunca salen de tu dispositivo."
date: 2026-02-05
lastmod: 2026-10-24
reviewed: false
keywords: ["esteganografía online", "ocultar texto en imagen", "esteganografía lsb", "mensaje oculto en foto", "decodificar mensaje oculto", "esteganografía png", "mensaje secreto en imagen", "herramienta esteganografía"]
tags: ["privacidad", "seguridad", "imágenes", "herramienta"]
app_category: "SecurityApplication"
tool_file: "/tools/steganography/"
tool_title: "Steganography Lab"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "En la pestaña **Ocultar Mensaje**, suelta una imagen o haz clic para elegirla (JPG, PNG, WebP o GIF). La herramienta muestra su tamaño y cuántos bytes admite."
  - "Escribe o pega tu mensaje. La barra de capacidad se llena mientras escribes y pasa a naranja y luego a rojo al acercarte al límite."
  - "Haz clic en **Codificar y Descargar PNG**. Se guarda un archivo `stego_<timestamp>.png`, visualmente idéntico al original."
  - "Envía ese PNG **como archivo** (adjunto de correo, enlace en la nube, \"enviar como documento\"), no como foto que una app de chat volverá a comprimir."
  - "Para leerlo, abre la pestaña **Revelar Mensaje**, carga el PNG y pulsa **Decodificar Mensaje Oculto**. Con **Copiar Texto** copias el resultado."
faq:
  - q: "¿El mensaje oculto está cifrado?"
    a: "No. La esteganografía oculta que existe un mensaje, pero no protege su contenido. Cualquiera que cargue el PNG en esta herramienta, o conozca el esquema, puede leerlo. Para algo sensible, cifra antes el texto (por ejemplo con age o GPG) y oculta el texto cifrado."
  - q: "¿Por qué la salida tiene que ser PNG?"
    a: "El PNG es sin pérdida: cada valor de píxel se guarda exactamente como se escribió. JPEG y WebP con pérdida recuantizan los colores al guardar y revuelven justo los bits bajos donde vive el mensaje. Por eso la pestaña de revelar solo acepta PNG."
  - q: "El mensaje desapareció tras enviar la imagen. ¿Por qué?"
    a: "La mayoría de apps de chat y redes sociales redimensionan y recomprimen las fotos, y una captura de pantalla vuelve a dibujar los píxeles. Cualquiera de estas cosas destruye los bits ocultos. Envía el PNG como archivo o documento para que llegue intacto byte a byte."
  - q: "¿Cuánto texto cabe en una imagen?"
    a: "Tres bits por cada píxel totalmente opaco, menos 19 bytes de cabecera y terminador. Una foto de 1920×1080 admite unos 777.000 bytes. El contador va en bytes UTF-8: las letras acentuadas usan dos y muchos emoji cuatro."
  - q: "¿Pueden detectarlo las herramientas de estegoanálisis?"
    a: "Sí. La inserción LSB secuencial es justo el caso que pruebas estadísticas como chi-cuadrado y el análisis RS detectan, sobre todo si se usa gran parte de la capacidad. Tómala como herramienta didáctica y de privacidad ligera, no de comunicación encubierta frente a un adversario capaz."
  - q: "¿Funciona con PNG transparentes?"
    a: "Sí. Solo los píxeles totalmente opacos llevan datos, porque el navegador guarda los semitransparentes en forma premultiplicada y sus bits bajos no sobrevivirían. Las zonas transparentes no se tocan y simplemente reducen la capacidad."
  - q: "¿Se sube mi imagen a algún sitio?"
    a: "No. El archivo se lee con la API FileReader y se procesa en un canvas dentro de la pestaña del navegador. No hay servidor: puedes cargar la página, quedarte sin conexión y sigue funcionando."
---

## Cómo funciona

La técnica es la **sustitución del bit menos significativo (LSB)**, la forma clásica de esteganografía en imágenes (hay una explicación más amplia en la [guía Esteganografía 101](/es/learn/guides/steganography-101-hidden-messages/)).

**1. Construir la carga.** Tu texto se codifica en UTF-8 y se envuelve así:

```
STEGO_V1::<tu mensaje>\0\0\0END\0\0\0
```

El prefijo `STEGO_V1::` permite al decodificador saber de inmediato si una imagen lleva un mensaje; el marcador `END` rodeado de bytes nulos indica dónde termina.

**2. Leer los píxeles.** La imagen se dibuja en un canvas HTML a su tamaño natural, con el suavizado desactivado, y `getImageData()` devuelve cada píxel como bytes de rojo, verde, azul y alfa.

**3. Un bit por canal de color.** Los bits de la carga, del más significativo al menos, se escriben uno a uno en el bit más bajo de los bytes R, G y B de cada píxel totalmente opaco, en orden de lectura desde la esquina superior izquierda. Cada byte pasa a ser `(valor & 0xFE) | bit`: un canal cambia 0 o 1 y la diferencia es invisible. El alfa nunca se toca y se saltan los píxeles no totalmente opacos, porque el canvas premultiplica sus colores y se perderían los bits bajos.

**4. Exportar sin pérdida.** El canvas modificado se guarda con `toBlob('image/png')`. Efecto secundario: la salida **no lleva metadatos EXIF** (cámara, GPS, fecha), ya que el canvas solo conoce píxeles.

**5. Decodificar.** La pestaña Revelar hace lo contrario: recoge los bits bajos de los mismos canales, reconstruye bytes y compara los diez primeros con `STEGO_V1::`. Si no coinciden se detiene enseguida, así que una foto grande y limpia se descarta casi al instante; si coinciden, lee hasta el marcador final y convierte los bytes en texto.

| Imagen | Píxeles opacos | Capacidad |
|---|---|---|
| 800×600 | 480.000 | ≈ 179.981 bytes |
| 1920×1080 | 2.073.600 | ≈ 777.581 bytes |
| 4000×3000 | 12.000.000 | ≈ 4,5 MB |

Cuanta más capacidad llenes, más fácil será marcar la imagen con estegoanálisis estadístico. Un mensaje corto en una foto grande y con ruido es mucho más difícil de detectar que uno largo en un gráfico de colores planos.

## Casos de uso

- **Aprender y enseñar.** Observa exactamente qué hace la inserción LSB y luego intenta romperla: recomprime el PNG como JPEG y verás desaparecer el mensaje.
- **Práctica de CTF.** Los retos de esteganografía suelen esconder flags en los LSB; codificar tus propias muestras hace que el patrón sea fácil de reconocer con herramientas como `zsteg` o StegSolve.
- **Marcar tus propias imágenes.** Inserta una nota (autor, fecha) en un PNG que compartes como archivo. No sobrevive a la edición, pero demuestra que una copia está intacta.
- **Un secreto en broma.** Oculta un mensaje en una foto de vacaciones para un amigo que sepa dónde mirar.
- **Transportar texto ya cifrado.** Pega un texto cifrado (por ejemplo salida GPG en ASCII armor) y obtén confidencialidad y bajo perfil a la vez.

Para el trabajo opuesto, eliminar datos ocultos en los metadatos de una foto en lugar de en sus píxeles, usa el [EXIF Cleaner](/es/tools/exif-cleaner/).
