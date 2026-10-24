---
title: "Secrets Scanner: Busca API Keys en Código"
description: "Pega un .env, un archivo de configuración o código y encuentra API keys, tokens, claves privadas y contraseñas expuestas antes del commit. Todo en local."
intro: "**SafeEnv** busca credenciales expuestas en un texto: claves de AWS, GitHub, Stripe, OpenAI y Slack, bloques de claves privadas, contraseñas en cadenas de conexión y valores de alta entropía junto a nombres como `SECRET` o `TOKEN`. Pega o arrastra un archivo: el análisis ocurre por completo en tu navegador."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["secrets scanner", "buscar api keys en código", "escáner de archivos env", "contraseñas hardcodeadas", "detectar credenciales expuestas", "fuga de token github", "detección de secretos online", "api key expuesta"]
tags: ["seguridad", "devsecops", "secretos", "herramienta"]
app_category: "DeveloperApplication"
tool_file: "/tools/secrets-scanner/"
tool_title: "SafeEnv, escáner de secretos"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Pega en el cuadro el contenido de un `.env`, `docker-compose.yml`, configuración de CI, archivo Terraform o fragmento de código, o usa **Scan a file…** o arrastra un archivo encima."
  - "Pulsa **Scan for secrets**. Un archivo de configuración típico se analiza en unos milisegundos."
  - "Lee las etiquetas de resumen (critical, high, medium, low, info) y la lista de hallazgos, ordenada por gravedad y después por número de línea."
  - "Cada hallazgo muestra la regla que coincidió, la línea, el valor enmascarado (solo los cuatro primeros y los cuatro últimos caracteres) y qué hacer."
  - "Corrige primero los críticos: rota la credencial, quítala del archivo y del historial de git y cárgala desde un gestor de secretos o una variable de entorno. **Copy report** te da un resumen en texto para un ticket."
faq:
  - q: "¿Es seguro pegar secretos reales en este escáner?"
    a: "El escáner es JavaScript que se ejecuta en esta página y no hace peticiones de red con tu texto, así que nada llega a nuestros servidores. En pantalla se muestran valores enmascarados, nunca los secretos completos. Aun así, si encuentras una clave real de producción, dala por comprometida y rótala."
  - q: "¿Qué tipos de secretos detecta?"
    a: "Veinte formatos concretos, entre ellos access key ID y secret key de AWS, tokens de GitHub y GitLab, claves de Stripe live y de prueba, API keys de Google, de OpenAI y de Anthropic, tokens y webhooks de Slack, claves de SendGrid, npm, PyPI, bots de Telegram y Twilio, JSON Web Tokens, bloques de claves privadas y credenciales dentro de URLs de bases de datos o HTTP. Una segunda pasada marca valores de alta entropía y contraseñas hardcodeadas en cualquier línea `CLAVE=VALOR`."
  - q: "¿Por qué se marca un valor como \"high entropy\"?"
    a: "Las cadenas de aspecto aleatorio son justo como se ven los secretos generados. El escáner calcula la entropía de Shannon de cada valor de 20 o más caracteres y lo marca a partir de 4,3 bits por carácter. Los valores junto a nombres que contienen secret, token, password, key o auth reciben más gravedad. Los hashes, UUID e IDs de compilación también pueden activarlo, así que mira el contexto."
  - q: "¿Qué hago si un secreto llegó a un commit de git?"
    a: "Borrar la línea en un commit nuevo no basta: el secreto sigue en el historial y en cada clon. Primero rota o revoca la credencial, después reescribe el historial con `git filter-repo` o BFG Repo-Cleaner, haz force-push y pide a los colaboradores que vuelvan a clonar. La rotación es el paso que de verdad te protege."
  - q: "¿Sustituye a herramientas como Gitleaks o el secret scanning de GitHub?"
    a: "No, las complementa. Usa un hook pre-commit o un escáner en CI para cada commit, y la push protection de GitHub en tus repositorios. SafeEnv sirve para los momentos intermedios: revisar un fragmento antes de pegarlo en un chat, un ticket o un asistente de IA, o revisar una configuración que alguien te ha enviado."
  - q: "¿Por qué los valores de marcador de posición aparecen como info?"
    a: "Líneas como `API_KEY=your-api-key-here` o `PASSWORD=${DB_PASSWORD}` tienen forma de secreto pero son plantillas. El escáner reconoce los patrones de marcador más comunes (your-, changeme, example, xxx, `${VAR}`, `<value>`) y los indica como info para que confirmes que son intencionados."
---

## Cómo funciona

El escáner es un pequeño motor de reglas sin dependencias que hace dos pasadas sobre el texto.

### Pasada 1: formatos de token conocidos

Veinte expresiones regulares reconocen formatos que los proveedores documentan públicamente, sobre todo por su prefijo fijo y su longitud. Algunos ejemplos de lo que buscan las reglas:

| Regla | Firma que reconoce | Gravedad |
|---|---|---|
| Bloque de clave privada | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, DSA, OpenSSH, PGP, cifrada) | Crítica |
| Access key ID de AWS | `AKIA`, `ASIA`, `ABIA` o `ACCA` seguidos de 16 mayúsculas o dígitos | Crítica |
| Secret access key de AWS | Un valor Base64 de 40 caracteres asignado a un nombre como `aws_secret_access_key` | Crítica |
| Token de GitHub | Prefijos `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` o `github_pat_` | Crítica |
| Clave live de Stripe | Prefijos `sk_live_` / `rk_live_` | Crítica |
| Clave de OpenAI / Anthropic | Prefijos `sk-proj-`, `sk-svcacct-`, `sk-ant-` | Crítica |
| API key de Google | `AIza` seguido de 35 caracteres | Alta |
| Token / webhook de Slack | Tokens `xox[baprs]-`, URLs `hooks.slack.com/services/…` | Alta |
| Credenciales en una URI | `postgres://usuario:contraseña@host`, también MySQL, MongoDB, Redis, AMQP, FTP y basic auth HTTP | Alta |
| JSON Web Token | Tres segmentos Base64URL que empiezan por `eyJ` | Media |
| Clave de prueba / publicable de Stripe | `sk_test_`, `pk_live_`, `pk_test_` | Baja |

Cada coincidencia registra el número de línea (contando los saltos de línea anteriores) y una versión **enmascarada** del valor, que solo conserva los cuatro primeros y los cuatro últimos caracteres: el propio informe nunca contiene el secreto.

### Pasada 2: análisis genérico `CLAVE=VALOR`

Las líneas que ninguna regla específica ha capturado se leen como asignaciones, la sintaxis de `.env`, YAML y casi todos los formatos de configuración (se gestionan prefijos `export`, comillas y comentarios `#` al final). Para cada valor de seis o más caracteres:

1. Si parece un **marcador de posición** (`your-…`, `changeme`, `example`, `xxxx`, `${VAR}`, `<value>`, `true/false/null`), se indica como *info* cuando el nombre de la clave parece de secreto, y si no se ignora.
2. Los valores con una URL o espacios se omiten, porque rara vez son secretos por sí solos.
3. Se calcula la **entropía de Shannon** H = −Σ p·log₂(p) sobre las frecuencias de caracteres. Un valor de 20+ caracteres con H ≥ 4,3 bits por carácter se marca como *high entropy*, con gravedad alta si el nombre contiene secret, token, passw, pwd, api_key, private, credential o auth, y media en otro caso.
4. Un valor de menor entropía asignado a un nombre tipo contraseña se indica como *hardcoded password*.

Los hallazgos se ordenan por gravedad y luego por línea. No se guarda nada: vacía el cuadro o cierra la pestaña y el texto desaparece.

### Límites

El análisis con regex encuentra *formatos*, no *validez*: no puede saber si una clave sigue activa. Tampoco ve secretos partidos en varias líneas, cifrados o codificados de forma inusual. Por eso es una comprobación rápida, no un sustituto del escaneo en tu pipeline de CI.

## Casos de uso

- **Antes de compartir un fragmento.** Revisa una configuración o un stack trace antes de pegarlo en Slack, un issue de GitHub, Stack Overflow o un chatbot de IA.
- **Antes del primer commit.** Analiza `.env.example`, `docker-compose.yml` y los archivos de CI de un proyecto nuevo para asegurarte de que no se ha colado ningún valor real.
- **Revisar una pull request o un traspaso.** Pega el diff de los archivos de configuración y busca cualquier cosa crítica.
- **Respuesta a incidentes.** Tras una posible fuga, analiza logs o configuraciones exportadas para listar todas las credenciales que hay que rotar.
- **Enseñar buenos hábitos.** El archivo de ejemplo muestra a un equipo, en segundos, cuántos secretos contiene un `.env` corriente.
