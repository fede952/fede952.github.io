---
title: "Conversor de Timestamp Unix (Epoch a Fecha)"
description: "Convierte timestamps Unix a fechas y fechas a tiempo epoch, en UTC y en hora local. Detecta segundos o milisegundos automáticamente. Reloj epoch en vivo."
intro: "**ChronoSync** convierte **timestamps Unix (epoch)** en fechas legibles y al revés. Muestra el timestamp actual avanzando en directo, acepta segundos o milisegundos y da cada resultado tanto en UTC como en tu zona horaria."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["conversor timestamp unix", "convertir epoch", "timestamp a fecha", "fecha a timestamp", "epoch time ahora", "unix time", "milisegundos a fecha", "conversor epoch"]
tags: ["herramientas-desarrollo", "tiempo", "conversor", "herramienta"]
app_category: "DeveloperApplication"
tool_file: "/tools/chrono-sync/"
tool_title: "ChronoSync, conversor de timestamps Unix"
tool_height: 700
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Mira el **Timestamp UNIX Actual** arriba: se actualiza cada segundo, con el mismo instante en UTC debajo."
  - "Para convertir un timestamp en fecha, pégalo en **Timestamp → Fecha** y pulsa **Convertir**. Los valores de 10 cifras se leen como segundos y los de 13 como milisegundos."
  - "Lee el resultado: primero la fecha en UTC y después el mismo instante en la zona horaria local de tu navegador."
  - "Para obtener un timestamp, elige fecha y hora en **Fecha → Timestamp** (hora local, al segundo) y pulsa **Convertir**."
  - "Usa el pequeño botón de copiar junto a cada resultado para llevarlo al portapapeles."
faq:
  - q: "¿Qué es un timestamp Unix?"
    a: "El número de segundos transcurridos desde las 00:00:00 UTC del 1 de enero de 1970, el \"epoch\" de Unix, sin contar segundos intercalares. En un instante dado es el mismo en todo el mundo, y por eso lo usan servidores, bases de datos y logs: 1700000000 es el 14 de noviembre de 2023 a las 22:13:20 UTC, estés en la zona horaria que estés."
  - q: "¿Segundos o milisegundos?"
    a: "Las herramientas Unix, PHP, `time.time()` de Python (como entero) y casi todas las bases de datos usan segundos, hoy 10 cifras. `Date.now()` de JavaScript, `System.currentTimeMillis()` de Java y muchas API usan milisegundos, 13 cifras. ChronoSync trata como milisegundos las entradas de 13 cifras o más y marca el resultado con (ms)."
  - q: "¿Por qué la fecha convertida parece desfasada una o dos horas?"
    a: "Porque un timestamp no tiene zona horaria; solo la tiene su representación. Compara la línea UTC, no la local, con tu servidor o tus logs, que suelen estar en UTC. El horario de verano explica las diferencias que solo aparecen parte del año."
  - q: "¿Qué es el problema del año 2038?"
    a: "Los sistemas que guardan timestamps como enteros con signo de 32 bits se desbordan en 2147483647, es decir, a las 03:14:07 UTC del 19 de enero de 2038. Después el valor pasa a negativo y las fechas saltan a 1901. Los sistemas modernos usan 64 bits, pero los dispositivos embebidos y los formatos de archivo antiguos siguen afectados."
  - q: "¿Funciona con fechas anteriores a 1970?"
    a: "Sí. Los timestamps negativos cuentan los segundos antes del epoch: -86400 es el 31 de diciembre de 1969 a las 00:00 UTC. Escribe el signo menos y convierte como siempre."
  - q: "¿Cómo obtengo el timestamp actual en código?"
    a: "Bash: `date +%s`. Python: `int(time.time())`. JavaScript: `Math.floor(Date.now() / 1000)`. PHP: `time()`. SQL (PostgreSQL): `extract(epoch from now())`. PowerShell: `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`."
---

## Cómo funciona

Todo es JavaScript con el objeto `Date` del navegador, que internamente guarda el tiempo como milisegundos desde el epoch.

**Reloj en directo.** Cada segundo la página calcula `Math.floor(Date.now() / 1000)` y lo muestra junto al `toISOString()` del mismo instante, con el formato `AAAA-MM-DD HH:MM:SS UTC`.

**Timestamp → fecha.** La entrada debe ser un entero, opcionalmente negativo. Si tiene 13 cifras o más se toma como milisegundos; si no, se multiplica por 1000. La `Date` resultante se muestra dos veces:

1. en **UTC**, con `toISOString()`, la forma sin ambigüedad para comparar con logs y servidores;
2. en **hora local**, con `toLocaleString()`, que usa la zona horaria y el formato de fecha de tu navegador.

**Fecha → timestamp.** El selector es un `<input type="datetime-local">`, que no tiene zona horaria propia: el navegador lo interpreta en tu zona local. `getTime() / 1000`, redondeado hacia abajo, da los segundos epoch. El selector viene ya relleno con la hora local actual.

| Timestamp | Fecha UTC | Nota |
|---|---|---|
| `0` | 1970-01-01 00:00:00 | El epoch |
| `1000000000` | 2001-09-09 01:46:40 | Primer timestamp de 10 cifras |
| `1700000000` | 2023-11-14 22:13:20 | |
| `2000000000` | 2033-05-18 03:33:20 | |
| `2147483647` | 2038-01-19 03:14:07 | Mayor valor con signo de 32 bits |
| `-86400` | 1969-12-31 00:00:00 | Un día antes del epoch |

Los segundos intercalares no forman parte del tiempo Unix, así que un timestamp corresponde a un único instante UTC (salvo el raro segundo intercalar) y dos timestamps difieren exactamente en su número de segundos.

## Casos de uso

- **Leer logs y JWT.** Convierte `exp`, `iat` y campos de log como `1729771200` en una fecha con la que razonar.
- **Depurar zonas horarias.** Comprueba de un vistazo si un valor guardado es la medianoche UTC o la local.
- **Escribir consultas.** Obtén el timestamp de "1 de marzo de 2026 00:00" para pegarlo en un `WHERE` de SQL o en un filtro de API.
- **Pasar entre lenguajes.** Verifica si un valor de JavaScript (ms) y otro de Python (s) describen el mismo momento.
- **Cron y planificación.** Comprueba cuándo se ejecutará de verdad una tarea programada en tiempo epoch.
