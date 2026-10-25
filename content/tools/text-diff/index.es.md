---
title: "Comparar textos online: encuentra cambios"
description: "Compara dos textos o archivos en paralelo o en línea, resalta palabras o caracteres, ignora espacios o mayúsculas y copia un diff unificado. Privado, local."
intro: "Pega dos versiones de un texto, un archivo de configuración o un fragmento de código para ver cada línea **añadida**, **eliminada** y **modificada**, **en paralelo** o **en línea**, con las **palabras** o los **caracteres** que cambian resaltados. Ignora espacios o mayúsculas, pliega las líneas sin cambios y **copia un diff unificado** que puedes aplicar con `git apply` o `patch`. Nada sale de tu navegador."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["comparar textos", "comparar dos textos", "diff online", "encontrar diferencias texto", "comparar archivos", "diff unificado", "text compare", "comparador de textos"]
tags: ["herramientas-desarrollo", "diff", "texto", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/text-diff/"
tool_title: "Comparador de textos (diff)"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Pega la versión antigua en **Original** y la nueva en **Modificado**, o carga cada una con **Abrir archivo**. Pulsa **Ejemplo** para probar con dos versiones de una configuración de nginx."
  - "El resultado se actualiza mientras escribes. Elige **En paralelo** para ver las dos versiones en columnas o **En línea** para una sola columna con líneas − y + (la opción por defecto en móviles)."
  - "Pon **Resaltar** en **Palabras** o **Caracteres** para elegir con qué precisión se marcan los cambios dentro de una línea modificada."
  - "Marca **Ignorar espacios** para que la sangría y los espacios repetidos cuenten como iguales, e **Ignorar mayúsculas** para no distinguir mayúsculas de minúsculas."
  - "Los tramos largos sin cambios se pliegan a tres líneas de contexto; haz clic en una barra *⋯ líneas sin cambios* para desplegarla. Usa **Copiar diff unificado** o **Descargar .diff** para compartir el cambio como parche."
faq:
  - q: "¿Se suben mis textos a algún sitio?"
    a: "No. La comparación se hace por completo en tu navegador con la biblioteca de código abierto jsdiff, servida desde este sitio. Nada de lo que pegas o abres se envía a un servidor, así que puedes comparar contratos, archivos de configuración con secretos o código privado."
  - q: "¿Qué diferencia hay entre resaltar palabras y caracteres?"
    a: "En ambos casos los textos se emparejan primero línea a línea. Dentro de cada línea modificada, el modo palabras marca palabras completas y signos de puntuación distintos: la opción más clara para prosa y casi todo el código. El modo caracteres marca caracteres sueltos y muestra una errata de una letra o un dígito cambiado en un identificador o número largo."
  - q: "¿Qué ignora exactamente \"Ignorar espacios\"?"
    a: "Los espacios al principio y al final de la línea y la cantidad de espacios entre palabras: `a  =  1` y `a = 1` cuentan como la misma línea y los bloques reindentados no aparecen como cambiados. Un espacio entre dos palabras que antes estaban juntas sigue siendo una diferencia. Las líneas en blanco se siguen comparando como líneas."
  - q: "¿Qué es un diff unificado y cómo se aplica?"
    a: "Es el formato de texto estándar para un cambio, usado por git, las herramientas de revisión de código y patch: cabeceras `---` y `+++`, y después bloques que empiezan con `@@` con las líneas eliminadas marcadas con − y las añadidas con +, más tres líneas de contexto. Guárdalo como archivo `.diff` y ejecuta `git apply cambio.diff` o `patch -p0 < cambio.diff`."
  - q: "¿Cómo decide que una línea se modificó y no se eliminó y añadió?"
    a: "Usa el algoritmo de diff de Myers sobre líneas completas para encontrar el menor conjunto de eliminaciones y añadidos. Cuando un bloque de líneas eliminadas va seguido directamente de líneas añadidas, se emparejan una a una como líneas modificadas. Si una pareja comparte menos de un 30 % aproximado del contenido, se muestra como sustituida, sin resaltado interno."
  - q: "¿Puede comparar archivos grandes?"
    a: "Sí, de varios megabytes. Los textos de más de unos 400.000 caracteres se comparan al pulsar Comparar en lugar de con cada tecla. La vista muestra hasta 4.000 filas; el diff unificado siempre contiene el resultado completo. Si dos textos son tan distintos que tardarían demasiado, se avisa en lugar de bloquear la página."
  - q: "¿Admite los finales de línea de Windows?"
    a: "Sí. Los finales de línea CRLF y CR se normalizan antes de comparar, así que el mismo archivo guardado en Windows y en Linux resulta idéntico. La falta de salto de línea al final se ignora en la vista y se indica en el diff unificado."
---

## Cómo funciona

### Primero las líneas, después palabras o caracteres

Los dos textos se dividen en líneas y se comparan con el **algoritmo de diff de Myers** (el de `git diff`), que encuentra la secuencia más corta de eliminaciones y añadidos para convertir el original en el texto modificado. Las líneas eliminadas seguidas directamente de líneas añadidas se emparejan como *modificadas* y cada pareja se vuelve a comparar token a token: palabras, espacios y signos de puntuación sueltos, o caracteres individuales. Solo se resaltan los tokens que difieren.

### Opciones que no reescriben tu texto

**Ignorar espacios** e **Ignorar mayúsculas** cambian cómo se *comparan* las líneas y los tokens, no lo que se muestra: cada columna enseña exactamente lo que pegaste. Así la vista sigue siendo fiel cuando, por ejemplo, se ha reindentado un bloque de código: las líneas coinciden y en la columna derecha sigues viendo la nueva sangría.

### Diff unificado

Los botones **Copiar diff unificado** y **Descargar .diff** generan un parche estándar con tres líneas de contexto, encabezado con los nombres de archivo si los abriste (si no, `original.txt` y `changed.txt`). Al aplicarlo al original se obtiene exactamente el texto modificado; las pruebas de esta herramienta lo comprueban con `git apply`.

## Casos de uso

- **Código y configuración.** Mira qué cambió entre dos versiones de un archivo de nginx, Docker Compose o YAML antes de desplegarlo, sin hacer commit.
- **Documentos y contratos.** Encuentra cada palabra editada entre dos borradores de un contrato, una política o un artículo.
- **Logs y exportaciones.** Compara dos salidas de comandos, exportaciones CSV o listas para detectar las filas que aparecieron o desaparecieron.
- **Compartir un cambio.** Convierte tu edición en un archivo `.diff` que un compañero puede aplicar con git o pegar en un ticket.
- **Comprobar un copia y pega.** Verifica que un script, una clave o un fragmento copiado entre sistemas llegó sin cambios invisibles; usa el modo caracteres para el máximo detalle.
