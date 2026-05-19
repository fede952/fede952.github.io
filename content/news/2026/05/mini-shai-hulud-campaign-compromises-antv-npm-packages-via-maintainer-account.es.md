---
title: "Campaña Mini Shai-Hulud compromete paquetes npm de @antv a través de cuenta de mantenedor"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "es"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes comprometen la cuenta de mantenedor de @antv 'atool' para publicar paquetes npm maliciosos, incluyendo echarts-for-react con 1.1 millones de descargas semanales, en la ola de ataques a la cadena de suministro Mini Shai-Hulud en curso."
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "ecosistema npm de @antv"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes comprometen la cuenta de mantenedor de @antv 'atool' para publicar paquetes npm maliciosos, incluyendo echarts-for-react con 1.1 millones de descargas semanales, en la ola de ataques a la cadena de suministro Mini Shai-Hulud en curso.

{{< cyber-report severity="High" source="The Hacker News" target="ecosistema npm de @antv" >}}

Investigadores de ciberseguridad han identificado una nueva campaña de ataque a la cadena de suministro de software dirigida al ecosistema npm de @antv. Los atacantes comprometieron la cuenta de mantenedor npm 'atool' para publicar versiones maliciosas de varios paquetes, incluyendo echarts-for-react, un envoltorio de React ampliamente utilizado para Apache ECharts con aproximadamente 1.1 millones de descargas semanales.

{{< ad-banner >}}

Esta campaña es parte de la ola de ataques Mini Shai-Hulud en curso, que previamente ha atacado otros ecosistemas de código abierto. Los paquetes comprometidos probablemente contienen código malicioso diseñado para exfiltrar datos sensibles o establecer puertas traseras en entornos de desarrollo.

Las organizaciones que utilicen cualquier paquete de @antv deben auditar inmediatamente sus dependencias en busca de signos de compromiso, rotar credenciales y revisar cambios recientes en sus archivos de bloqueo. El alcance total de los paquetes afectados y la carga útil exacta aún están bajo investigación.

{{< netrunner-insight >}}

Este ataque subraya la necesidad crítica de medidas de seguridad en la cadena de suministro, como la verificación de integridad de paquetes, la autenticación multifactor para cuentas de mantenedor y el escaneo automatizado de dependencias. Los analistas del SOC deben priorizar la monitorización de tráfico saliente anómalo desde los pipelines de compilación, mientras que los equipos de DevSecOps deben imponer controles de acceso estrictos en las cuentas de publicación de paquetes.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
