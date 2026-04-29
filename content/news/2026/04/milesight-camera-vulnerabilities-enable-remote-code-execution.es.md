---
title: "Vulnerabilidades en cámaras Milesight permiten ejecución remota de código"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "es"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre múltiples modelos de cámaras Milesight afectados por vulnerabilidades críticas (CVE-2026-28747, etc.) que podrían provocar fallos del dispositivo o ejecución remota de código."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Cámaras IP Milesight"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre múltiples modelos de cámaras Milesight afectados por vulnerabilidades críticas (CVE-2026-28747, etc.) que podrían provocar fallos del dispositivo o ejecución remota de código.

{{< cyber-report severity="Critical" source="CISA" target="Cámaras IP Milesight" cve="CVE-2026-28747" >}}

CISA ha publicado un aviso (ICSA-26-113-03) que detalla múltiples vulnerabilidades que afectan a una amplia gama de modelos de cámaras Milesight. Las fallas, identificadas como CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649 y CVE-2026-20766, impactan versiones de firmware en varias líneas de productos, incluidas MS-Cxx63-PD, MS-Cxx64-xPD y otras. Una explotación exitosa podría permitir a un atacante bloquear el dispositivo o lograr ejecución remota de código.

{{< ad-banner >}}

Los modelos afectados abarcan múltiples series, con versiones de firmware hasta 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3 y otras. Dada la naturaleza crítica de la ejecución remota de código, estas vulnerabilidades representan un riesgo significativo para las organizaciones que utilizan cámaras Milesight en despliegues de vigilancia o IoT. CISA recomienda a los usuarios aplicar los parches disponibles y seguir las indicaciones del fabricante para mitigar la exposición.

Si bien no se proporcionan puntuaciones CVSS ni evidencia de explotación activa en el aviso, el potencial de compromiso del dispositivo e intrusión en la red merece atención inmediata. Los equipos de seguridad deben inventariar los modelos de cámaras afectados, segmentar los dispositivos IoT de las redes críticas y priorizar las actualizaciones de firmware.

{{< netrunner-insight >}}

Para los analistas del SOC, monitoreen el tráfico anómalo proveniente de subredes de cámaras y asegúrense de que estos dispositivos estén aislados. Los ingenieros de DevSecOps deben acelerar el parcheo de todas las cámaras Milesight, ya que las vulnerabilidades de ejecución remota de código en dispositivos periféricos a menudo se convierten en puntos de entrada para movimientos laterales. Traten estos CVE como críticos hasta que se verifiquen los parches del fabricante.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
