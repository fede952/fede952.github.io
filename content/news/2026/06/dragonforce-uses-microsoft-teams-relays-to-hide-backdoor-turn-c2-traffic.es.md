---
title: "DragonForce utiliza retransmisiones de Microsoft Teams para ocultar el tráfico C2 de Backdoor.Turn"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "es"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "El grupo de ransomware DragonForce despliega un RAT personalizado basado en Go llamado Backdoor.Turn, ocultando el tráfico C2 dentro de retransmisiones de Microsoft Teams, dirigido a una importante empresa de servicios estadounidense."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Importante empresa de servicios estadounidense"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El grupo de ransomware DragonForce despliega un RAT personalizado basado en Go llamado Backdoor.Turn, ocultando el tráfico C2 dentro de retransmisiones de Microsoft Teams, dirigido a una importante empresa de servicios estadounidense.

{{< cyber-report severity="High" source="The Hacker News" target="Importante empresa de servicios estadounidense" >}}

Se ha observado que actores de amenazas asociados con el grupo de ransomware DragonForce utilizan un troyano de acceso remoto (RAT) personalizado basado en Go llamado Backdoor.Turn para ocultar el tráfico de comando y control (C2) dentro de la infraestructura de retransmisión de Microsoft Teams. El backdoor fue desplegado contra una importante empresa de servicios estadounidense, según hallazgos de Symantec y Carbon Black, propiedad de Broadcom.

{{< ad-banner >}}

Al aprovechar las retransmisiones legítimas de Microsoft Teams, los atacantes pueden mezclar el tráfico malicioso con las comunicaciones comerciales normales, dificultando la detección para los defensores de la red. El RAT basado en Go proporciona a los atacantes acceso persistente y la capacidad de ejecutar comandos, exfiltrar datos y desplegar cargas útiles adicionales.

Esta técnica resalta la evolución de las tácticas de los grupos de ransomware para evadir las herramientas tradicionales de monitoreo de red. Las organizaciones que utilizan Microsoft Teams deben revisar sus configuraciones de seguridad y monitorear patrones anómalos de tráfico de retransmisión.

{{< netrunner-insight >}}

Los analistas del SOC deben monitorear el tráfico inusual de retransmisión de Microsoft Teams, especialmente desde endpoints no estándar o fuera del horario laboral. Los equipos de DevSecOps deben aplicar listas blancas de aplicaciones estrictas e inspeccionar el tráfico de Teams en busca de túneles cifrados que puedan indicar comunicación C2. Este ataque subraya la necesidad de principios de confianza cero incluso para plataformas de colaboración confiables.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
