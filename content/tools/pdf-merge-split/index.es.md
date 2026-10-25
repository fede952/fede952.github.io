---
title: "Unir y dividir PDF online, gratis y privado"
description: "Une archivos PDF, divídelos por páginas o rangos, reordena, gira y elimina páginas en tu navegador. Tus PDF nunca se suben. Gratis y sin registro."
intro: "**Une PDF** en un solo archivo, **divide un PDF** en páginas sueltas o rangos y, de paso, reordena, gira o elimina páginas, con miniaturas que puedes arrastrar. Todo ocurre en esta pestaña del navegador: contratos, nóminas y escaneos nunca salen de tu dispositivo."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["unir pdf", "dividir pdf", "juntar archivos pdf", "ordenar páginas pdf", "dividir pdf online", "unir pdf sin subir", "extraer páginas de pdf", "girar páginas pdf"]
tags: ["pdf", "privacidad", "documentos", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/pdf-merge-split/"
tool_title: "Unir, dividir y ordenar PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Suelta uno o varios PDF en el recuadro o haz clic para elegirlos. Cada página aparece como una miniatura numerada, en el orden de los archivos."
  - "Organiza las páginas: arrastra una miniatura a otra posición o usa los botones **←** y **→** (prácticos en el móvil). **⟳** gira una página 90° y **✕** la deja fuera del resultado."
  - "Para juntarlo todo, pon el **Nombre del archivo** y pulsa **Unir y descargar**: obtienes un solo PDF con las páginas tal como las ordenaste."
  - "Para dividir, elige **Cada página en un PDF aparte**, o **Por rangos de páginas** y escribe grupos como `1-3, 4, 5-` (los números son los de las miniaturas; `5-` significa de la página 5 al final)."
  - "Pulsa **Dividir y descargar (.zip)**. Cada grupo se convierte en un PDF con el nombre del primer archivo (`informe-part-1.pdf`…); con un solo grupo recibes directamente el PDF."
faq:
  - q: "¿Se suben mis PDF a algún sitio?"
    a: "No. El navegador lee los archivos, los previsualiza con pdf.js y los reconstruye con pdf-lib, ambos ejecutándose en esta pestaña. La página descarga esas bibliotecas una vez y no envía nada; puedes vigilar el panel Red mientras unes para comprobarlo."
  - q: "¿Unir PDF reduce la calidad?"
    a: "No. Las páginas se copian tal cual: el texto sigue siendo texto, las imágenes mantienen su compresión original y se conservan las fuentes. Nada se rasteriza ni se vuelve a comprimir, así que el resultado es tan nítido como los originales."
  - q: "¿Puedo unir PDF protegidos con contraseña?"
    a: "No directamente: un PDF cifrado no se puede leer sin su contraseña, y la herramienta lo indica en lugar de generar un archivo dañado. Ábrelo en un lector de PDF, guarda una copia sin contraseña y añade esa copia."
  - q: "¿Se conservan enlaces, marcadores y campos de formulario?"
    a: "Se copian el contenido de las páginas, las anotaciones y los enlaces de las páginas. El índice (marcadores) y la lógica de los formularios interactivos pertenecen al archivo original completo y no se reconstruyen en el PDF unido, así que revisa los formularios después de unir."
  - q: "¿Qué tamaño pueden tener los archivos?"
    a: "No hay un límite fijo; depende de la memoria del dispositivo. Documentos de unos cientos de páginas funcionan bien en un ordenador. Se genera una miniatura por página, así que los archivos muy grandes tardan más en aparecer."
  - q: "¿Qué le hace al archivo la rotación?"
    a: "Fija la rotación de la página en el PDF (en pasos de 90°), que todos los lectores respetan. El contenido no se redibuja, así que girar no tiene pérdida y se deshace volviendo a girar."
  - q: "¿Cómo extraigo solo algunas páginas?"
    a: "Usa **Por rangos de páginas** con un solo grupo, por ejemplo `3-5`: descargas un PDF que contiene solo las páginas 3, 4 y 5. También puedes quitar con ✕ las páginas que no quieras y unir."
---

## Cómo funciona

### Dos bibliotecas, ambas locales

Leer un PDF y escribir uno son tareas distintas, así que la herramienta usa dos bibliotecas de código abierto, servidas desde este sitio y cargadas solo cuando añades un archivo:

- **pdf.js** (Mozilla, Apache-2.0), el motor del visor de PDF de Firefox, genera una pequeña miniatura de cada página en un worker en segundo plano para que la página siga respondiendo.
- **pdf-lib** (MIT) construye el resultado. Para cada página, en tu orden, copia el objeto de página del documento de origen —flujos de contenido, fuentes, imágenes y anotaciones— a un documento nuevo con `copyPages`, aplica la rotación elegida y guarda.

Antes de nada, la herramienta comprueba que cada archivo empiece por `%PDF-`, de modo que un documento de Word renombrado o una descarga dañada se notifica con su nombre.

### Orden de páginas y rangos

Las miniaturas forman una sola lista para todos los archivos: al unir se escriben en ese orden, y los números que escribes para dividir también se refieren a ella. Los rangos son grupos separados por comas; cada grupo puede ser una página suelta (`4`), un intervalo (`1-3`), un final abierto (`5-` hasta la última página) o un inicio abierto (`-3`). Cada grupo se convierte en un PDF; varios PDF se empaquetan en un ZIP con JSZip.

### Qué no se incluye

El documento nuevo recibe metadatos nuevos de pdf-lib en lugar de los títulos y autores de origen, y las funciones a nivel de documento, como el índice de marcadores y los scripts de formularios, no se recrean. Para unir y dividir en el día a día —facturas, escaneos, capítulos, diapositivas— es justo lo que necesitas.

## Casos de uso

- **Juntar escaneos** de un contrato o formulario de varias páginas en un solo archivo antes de enviarlo por correo.
- **Dividir un PDF grande** —un libro de texto, un manual, un año de extractos bancarios— en capítulos o meses.
- **Quitar páginas** con datos personales antes de compartir un documento.
- **Corregir el orden y la orientación** de un documento escaneado del revés o desordenado.
- **Preparar una candidatura**: CV, carta de presentación y certificados en el orden que pide la empresa, sin entregarlos a un servicio online del que no sabes nada.
