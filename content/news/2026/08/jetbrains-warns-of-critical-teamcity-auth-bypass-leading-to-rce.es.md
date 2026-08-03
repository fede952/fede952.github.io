---
title: "JetBrains advierte sobre una omisión crítica de autenticación en TeamCity que conduce a RCE"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "es"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "JetBrains advierte sobre una omisión crítica de autenticación en TeamCity On-Premises que podría permitir la ejecución remota de código. Se recomienda aplicar parches de inmediato."
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

JetBrains advierte sobre una omisión crítica de autenticación en TeamCity On-Premises que podría permitir la ejecución remota de código. Se recomienda aplicar parches de inmediato.

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

JetBrains ha emitido una advertencia sobre una vulnerabilidad crítica de omisión de autenticación que afecta a TeamCity On-Premises. Esta falla podría ser explotada por un atacante no autenticado para lograr la ejecución remota de código en el servidor afectado, lo que representa un riesgo grave para las organizaciones que dependen de TeamCity para sus pipelines de compilación e integración continua.

{{< ad-banner >}}

La vulnerabilidad es particularmente preocupante porque los servidores de TeamCity a menudo contienen código fuente sensible, artefactos de compilación y credenciales, lo que los convierte en objetivos de alto valor para los atacantes. Una explotación exitosa podría llevar al compromiso total del servidor y potencialmente de la infraestructura más amplia si el servidor no está adecuadamente aislado.

Las organizaciones que utilizan TeamCity On-Premises deben priorizar la aplicación de las actualizaciones de seguridad proporcionadas por el proveedor de inmediato. Hasta que se apliquen los parches, se recomienda restringir el acceso de red al servidor de TeamCity y monitorear cualquier actividad sospechosa.

{{< netrunner-insight >}}

Esta es una vulnerabilidad crítica que debe tratarse como una emergencia. Los analistas del SOC deben verificar inmediatamente si su organización utiliza TeamCity On-Premises y confirmar el estado de los parches. Dado el potencial de RCE no autenticado, asuma que el servidor está comprometido si está expuesto y realice una revisión forense exhaustiva. Los equipos de DevSecOps también deberían considerar segmentar los servidores de compilación y aplicar controles de acceso estrictos para mitigar el radio de explosión.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
