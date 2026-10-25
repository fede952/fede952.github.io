---
title: "Formateador y validador JSON, JSON a YAML"
description: "Formatea, minifica y valida JSON con errores en línea y columna exactas, ordena claves, explóralo como árbol y conviértelo a YAML o CSV. Privado, local."
intro: "Pega JSON para **formatearlo** con 2 o 4 espacios o tabuladores, **minificarlo**, **validarlo** con la *línea y columna* exactas del primer error, **ordenar las claves**, recorrerlo como **árbol** plegable o convertir **JSON a YAML**, **YAML a JSON** y **JSON a CSV**. Los archivos de varios megabytes los procesa un worker en segundo plano; no se sube nada."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["formateador json", "validador json", "formatear json online", "json beautifier", "json a yaml", "yaml a json", "json a csv", "minificar json"]
tags: ["herramientas-desarrollo", "json", "yaml", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-formatter/"
tool_title: "Formateador, validador y conversor JSON"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Pega tu JSON en **Entrada**, abre un archivo `.json` con **Abrir archivo** o pulsa **Ejemplo** para probar."
  - "Pulsa **Formatear** (o Ctrl/⌘ + Intro) para indentarlo con la **Sangría** elegida; **Minificar** quita todos los espacios. Marca **Ordenar claves** para ordenar alfabéticamente las claves de cada objeto."
  - "Si el JSON no es válido, la línea de estado indica el problema y su posición —por ejemplo *Línea 3, columna 14: coma final*— y muestra la línea afectada con una marca bajo el carácter exacto."
  - "Convierte con **A YAML** o **A CSV** (elige el **Separador CSV**). Para el camino inverso, cambia a **Entrada YAML**, pega YAML y pulsa **Formatear** para obtener JSON."
  - "Alterna la salida entre **Texto** y **Árbol** para recorrer estructuras grandes, y luego **Copiar** o **Descargar** el resultado."
faq:
  - q: "¿Se envía mi JSON a un servidor?"
    a: "No. El análisis, el formato y la conversión se hacen en tu navegador; las entradas de más de 2 MB, en un Web Worker de la misma pestaña. La página no hace ninguna petición con tus datos, así que respuestas de API, tokens y archivos de configuración se quedan en tu equipo."
  - q: "¿Por qué dice \"coma final\"?"
    a: "JSON no permite una coma tras el último elemento de un objeto o array, aunque JavaScript sí. `[1, 2,]` y `{\"a\": 1,}` no son JSON válido: quita la última coma. Otros errores frecuentes que el validador reconoce: comillas simples, claves sin comillas, comentarios y valores NaN o Infinity."
  - q: "¿Cómo encuentra la línea y la columna de un error?"
    a: "Los mensajes de JSON.parse varían entre navegadores y algunos solo dan una posición en caracteres. Cuando el análisis falla, la herramienta vuelve a leer el texto con su propio analizador estricto según la RFC 8259, que se detiene en el primer carácter imposible en un JSON válido e informa de su línea y columna."
  - q: "¿Cómo se convierte JSON a CSV?"
    a: "Un array de objetos se convierte en una fila por objeto. Los objetos anidados pasan a columnas con punto (`address.city`), los arrays dentro de una fila se escriben como texto JSON y las columnas son la unión de todas las claves en el orden en que aparecen. Los valores con comas, comillas o saltos de línea se entrecomillan según la RFC 4180. Un array de arrays se escribe fila a fila."
  - q: "¿Se conservan los comentarios y anclas YAML al convertir?"
    a: "De YAML a JSON, las anclas y los alias se resuelven en valores normales y los comentarios se pierden, porque JSON no tiene ninguno de los dos. De JSON a YAML se obtiene YAML en bloques sin anclas, así que las estructuras repetidas se escriben completas."
  - q: "¿Ordenar las claves cambia mis datos?"
    a: "No cambia ningún valor. Las claves de los objetos se reordenan por punto de código Unicode (las mayúsculas antes que las minúsculas) en todos los niveles; los arrays conservan su orden, porque el orden forma parte del dato. La salida ordenada es útil para los diffs y para archivos estables en control de versiones."
  - q: "¿Qué tamaño de archivo admite?"
    a: "Decenas de megabytes en un ordenador. A partir de 2 MB, el formateo y la minificación se ejecutan en un worker en segundo plano para que la página siga respondiendo. La vista de árbol crea los nodos solo al abrirlos y muestra como máximo 500 hijos por nodo a la vez."
---

## Cómo funciona

### Una validación que se explica

La entrada se analiza con el `JSON.parse` nativo del navegador, el analizador más rápido y fiel al estándar disponible. Cuando falla, un segundo analizador, deliberadamente pequeño, recorre el texto siguiendo la gramática de la RFC 8259 —objetos, arrays, cadenas con sus reglas de escape, números sin ceros a la izquierda, `true`, `false`, `null`— y se detiene en el primer carácter que no puede continuar un documento válido. Esa posición se convierte en línea y columna y se asocia a una explicación clara: una coma final, dos puntos que faltan, una cadena con comillas simples, un tabulador sin escapar dentro de una cadena o texto después del final del documento.

### Formatear, minificar y ordenar

El formateo usa `JSON.stringify` con la sangría elegida (2 espacios, 4 espacios o un tabulador). Minificar escribe la misma estructura sin espacios. **Ordenar claves** reconstruye cada objeto con sus claves en orden de punto de código antes de serializar; el orden de los arrays nunca cambia. Los números se escriben como los lee JavaScript, así que los enteros por encima de 2^53 pierden precisión: guarda esos ID como cadenas.

### Entradas grandes

Por encima de 2 MB en UTF-8, el formateo y la minificación pasan a un **Web Worker**, un hilo en segundo plano de la misma pestaña, para que escribir y desplazarse sigan siendo fluidos mientras se procesa un volcado grande de una API. La vista de árbol se construye bajo demanda: los hijos de un nodo se crean solo al desplegarlo.

### Conversiones

La compatibilidad con YAML la aporta **js-yaml** (MIT), servida desde este sitio y cargada solo la primera vez que usas YAML. El YAML se lee con el esquema seguro por defecto, así que no puede crear objetos personalizados ni ejecutar código. El CSV lo genera la propia herramienta, con el entrecomillado y los finales de línea de la RFC 4180.

## Casos de uso

- **Depurar APIs.** Formatea una respuesta en una sola línea, encuentra en el árbol el campo que necesitas o localiza exactamente dónde se rompe un payload editado a mano.
- **Configuración.** Convierte un fragmento de Kubernetes o Docker Compose entre YAML y JSON, o valida un `package.json` o `tsconfig.json` tras editarlo.
- **Exportar datos.** Convierte un array de registros a CSV para una hoja de cálculo, con los campos anidados aplanados en columnas.
- **Revisión de código y control de versiones.** Ordena las claves y formatea de forma coherente para que los diffs muestren cambios reales y no reordenaciones.
- **Datos sensibles.** Inspecciona payloads de JWT, cuerpos de webhooks o logs con datos personales sin pegarlos en una web de terceros.
