---
title: "Generador de Expresiones Cron Explicadas"
description: "Crea expresiones cron de forma visual, tradúcelas a lenguaje sencillo y mira las próximas 5 ejecuciones. Generador de crontab gratis para Linux y CI."
intro: "**EasyCron** construye una expresión cron a golpe de clic, traduce a lenguaje sencillo una que ya tengas y muestra sus próximas cinco ejecuciones. Cubre la sintaxis estándar de crontab de cinco campos que usan cron en Linux, los CronJobs de Kubernetes y la mayoría de planificadores de CI."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["generador cron", "expresión cron", "crontab generator", "cron cada 5 minutos", "ejemplos crontab", "explicar expresión cron", "programar tareas cron", "próxima ejecución cron"]
tags: ["linux", "devops", "cron", "herramienta"]
app_category: "DeveloperApplication"
tool_file: "/tools/easy-cron/"
tool_title: "EasyCron, generador de expresiones cron"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Empieza con un **preset** (cada 5 minutos, días laborables a las 9, mensual el día 1…) o con el predeterminado `* * * * *`."
  - "Usa las pestañas **Minute, Hour, Day, Month, Weekday** para fijar cada campo: todos los valores, un intervalo como cada 15 minutos o valores concretos elegidos en una cuadrícula. Los botones rápidos cubren opciones comunes como horario de oficina o días laborables."
  - "Observa cómo la expresión, su descripción y las **Next 5 runs** se actualizan con cada clic."
  - "Pulsa **Copy** y pega la expresión en tu crontab, en el manifiesto del CronJob o en el archivo de CI."
  - "Para entender una programación existente, pégala en el **Reverse Translator** y pulsa **Parse**: obtienes la descripción y las próximas ejecuciones, y el constructor la carga para editarla."
faq:
  - q: "¿Qué significan los cinco campos de una expresión cron?"
    a: "Por orden: minuto (0–59), hora (0–23), día del mes (1–31), mes (1–12) y día de la semana (0–6, domingo = 0). `30 2 * * 1` significa, por tanto, a las 02:30 de cada lunes. Un asterisco quiere decir \"cualquier valor\" en ese campo."
  - q: "¿Cómo ejecuto una tarea cron cada 5 minutos?"
    a: "`*/5 * * * *`. El `*/5` del campo de minutos significa cada quinto minuto empezando en 0: 00, 05, 10 … 55. Del mismo modo, `0 */2 * * *` se ejecuta en punto cada dos horas y `*/15 9-17 * * 1-5` cada 15 minutos en horario de oficina los días laborables."
  - q: "¿Qué pasa si fijo a la vez el día del mes y el día de la semana?"
    a: "El cron estándar (Vixie) ejecuta la tarea cuando coincide *cualquiera de los dos*, no cuando coinciden ambos. `0 9 1 * 1` se ejecuta a las 09:00 el día 1 de cada mes *y* todos los lunes. El cálculo de próximas ejecuciones de EasyCron sigue la misma regla, que sorprende a mucha gente."
  - q: "¿En qué zona horaria se muestran las próximas ejecuciones?"
    a: "En la zona horaria de tu navegador. Un demonio cron usa la de la máquina donde se ejecuta, a menudo UTC en servidores y contenedores. Los CronJobs de Kubernetes usan la del controlador salvo que fijes `spec.timeZone`. Si tu servidor está en UTC, convierte antes de fiarte de la lista."
  - q: "¿EasyCron admite segundos, nombres como MON o JAN, o @daily?"
    a: "No. Está pensado para la sintaxis portable de cinco campos: números, `*`, rangos como `1-5`, listas como `1,15`, pasos como `*/10` y rangos con paso como `0-30/10`. Los segundos al estilo Quartz y `L`, `W`, `#`, `?` no están soportados. Escribe `0 0 * * *` en lugar de `@daily` y usa `0` (no `7`) para el domingo."
  - q: "¿Se envía algo a un servidor?"
    a: "No. El constructor, la descripción y el cálculo de ejecuciones son JavaScript dentro de esta página. Lo único que se guarda es tu preferencia de tema claro u oscuro, en el localStorage del navegador."
---

## Cómo funciona

### Construir la expresión

Cada uno de los cinco campos tiene su propio estado: **every** (`*`), **interval** (`*/n`, con opciones razonables para cada campo, como 5, 10, 15 o 30 minutos y 2, 3, 4, 6, 8 o 12 horas) o valores **concretos** elegidos en una cuadrícula. En modo concreto, los números seleccionados se ordenan y se unen con comas (`0,15,30,45`). Si están seleccionados todos los valores posibles, el campo vuelve a ser `*`. Las cinco partes se unen con espacios en la expresión final.

### Interpretar y explicar

El traductor inverso divide la expresión por los espacios y exige exactamente cinco campos. Cada campo se expande al conjunto de valores que abarca:

| Sintaxis | Ejemplo | Se expande a |
|---|---|---|
| `*` | `*` en horas | 0, 1, 2 … 23 |
| `*/n` | `*/15` en minutos | 0, 15, 30, 45 |
| `a-b` | `1-5` en días de la semana | lun … vie |
| `a-b/n` | `0-30/10` en minutos | 0, 10, 20, 30 |
| lista | `1,15` en días | día 1 y 15 |

La descripción (en inglés) se arma con reglas que suenan como lo diría una persona: `*/5 * * * *` pasa a "Every 5 minutes", `0 9 * * 1-5` a "At 09:00, Monday through Friday" y `0 0 1 1 *` a "At 00:00, on day 1 of the month, in January".

### Calcular las próximas ejecuciones

A partir de dentro de un minuto, el calculador avanza en el tiempo saltando unidades enteras que no pueden coincidir: un mes fuera del conjunto salta al día 1 del mes siguiente, un día que no coincide salta a la medianoche del día siguiente y una hora que no coincide, a la hora siguiente. Cuando mes, día, hora y minuto coinciden, se anota la fecha, hasta encontrar cinco ejecuciones o recorrer cuatro años. Por eso las programaciones imposibles como `0 0 31 2 *` (31 de febrero) indican que no hay próximas ejecuciones.

La comprobación del día sigue la semántica real de cron: si solo uno de los dos campos de día está restringido, decide ese; si lo están ambos, basta con que coincida uno.

## Casos de uso

- **Escribir una línea de crontab** para copias de seguridad, rotación de logs, renovación de certificados o un script de limpieza sin volver a buscar el orden de los campos.
- **CronJobs de Kubernetes y pipelines de CI.** `schedule:` de GitHub Actions, las programaciones de pipelines de GitLab y `spec.schedule` de Kubernetes usan los mismos cinco campos.
- **Revisar la programación de otra persona.** Pega el críptico `15 3 */2 * *` de una configuración y lee "At 03:15, every 2nd day of the month".
- **Detectar errores antes de producción**, como una tarea pensada para "días laborables a las 9" que también se ejecuta el día 1 del mes porque se fijaron los dos campos de día.
- **Planificar ventanas de mantenimiento.** Comprueba exactamente cuándo caen las próximas cinco ejecuciones y ajusta según la zona horaria del servidor.
