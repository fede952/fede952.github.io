---
title: "Laboratorio de Esteganografia"
description: "Oculta texto secreto dentro de imagenes usando codificacion LSB (Bit Menos Significativo). Codifica y decodifica mensajes ocultos, exporta como PNG. 100% lado cliente, sin subidas."
image: "/images/tools/stego-tool.png"
date: 2026-02-05
hidemeta: true
showToc: false
keywords: ["esteganografia", "ocultar texto en imagen", "codificacion LSB", "mensaje secreto", "esteganografia de imagenes", "codificar decodificar", "datos ocultos", "esteganografia png", "herramienta privacidad", "comunicacion encubierta"]
draft: false
---

La esteganografia es el arte de ocultar informacion a plena vista — incrustar datos secretos dentro de medios de apariencia inocente para que su propia existencia permanezca sin detectar. A diferencia del cifrado, que convierte los datos en texto cifrado obvio, la esteganografia oculta el *hecho* de que existe un secreto. Esta tecnica se ha utilizado durante siglos, desde tinta invisible en papel hasta micropuntos durante la Segunda Guerra Mundial, y ahora vive en el ambito digital.

**Laboratorio de Esteganografia** usa codificacion LSB (Bit Menos Significativo) para ocultar texto dentro de imagenes. Al modificar el bit menos significativo de cada canal de color (RGB), la herramienta puede incrustar miles de caracteres en una imagen con cambios imperceptibles al ojo humano. Carga cualquier imagen, escribe tu mensaje secreto y descarga un PNG con los datos ocultos dentro. Para recuperar el mensaje, simplemente carga el PNG codificado en la pestana "Revelar". Todo se ejecuta localmente en tu navegador — sin servidor, sin subidas, privacidad completa.

<iframe src="/tools/steganography/index.html" width="100%" height="900px" style="border:none; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);" sandbox="allow-scripts allow-same-origin allow-downloads allow-popups"></iframe>
