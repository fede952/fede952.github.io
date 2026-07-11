---
title: "Tres fallos de OpenClaw permiten una cadena de ataque de WhatsApp al host"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "es"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "Un investigador detalla tres vulnerabilidades de alta gravedad en OpenClaw que podrían permitir el robo de credenciales, la escalada de privilegios y la ejecución de código en el host."
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "Asistente de IA OpenClaw"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un investigador detalla tres vulnerabilidades de alta gravedad en OpenClaw que podrían permitir el robo de credenciales, la escalada de privilegios y la ejecución de código en el host.

{{< cyber-report severity="High" source="The Hacker News" target="Asistente de IA OpenClaw" cvss="8.8" >}}

Han surgido detalles sobre tres fallos de seguridad ya parcheados en el asistente de IA personal OpenClaw que, si se explotan con éxito, podrían permitir el robo de credenciales, la escalada de privilegios y la ejecución arbitraria de código en el host. Las vulnerabilidades fueron reveladas por un investigador que describió una cadena de ataque que comienza con mensajes de WhatsApp.

{{< ad-banner >}}

Uno de los fallos, registrado como GHSA-hjr6-g723-hmfm con una puntuación CVSS de 8.8, se describe como de alta gravedad. La naturaleza exacta de las otras dos vulnerabilidades no se ha detallado por completo, pero en conjunto representan un riesgo significativo para los usuarios que integran OpenClaw con plataformas de mensajería como WhatsApp.

La cadena de ataque aprovecha la capacidad del asistente de IA para procesar mensajes, lo que potencialmente permite a un atacante escalar privilegios y ejecutar código arbitrario en el sistema host. Se recomienda a los usuarios aplicar los últimos parches para mitigar estos riesgos.

{{< netrunner-insight >}}

Esta cadena de ataque resalta los riesgos de integrar asistentes de IA con plataformas de mensajería. Los analistas del SOC deben monitorear ejecuciones de procesos inusuales que se originen en componentes del asistente de IA, mientras que los equipos de DevSecOps deben asegurarse de que dichas integraciones estén en entornos aislados y parcheadas rápidamente.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
