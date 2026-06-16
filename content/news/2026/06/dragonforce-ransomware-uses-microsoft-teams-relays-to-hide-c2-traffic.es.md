---
title: "El ransomware DragonForce utiliza retransmisiones de Microsoft Teams para ocultar el tráfico C2"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "es"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "El ransomware DragonForce despliega el malware personalizado 'Backdoor.Turn' para ocultar el tráfico de comando y control dentro de la infraestructura de retransmisión de Microsoft Teams."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Infraestructura de retransmisión de Microsoft Teams"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El ransomware DragonForce despliega el malware personalizado 'Backdoor.Turn' para ocultar el tráfico de comando y control dentro de la infraestructura de retransmisión de Microsoft Teams.

{{< cyber-report severity="High" source="BleepingComputer" target="Infraestructura de retransmisión de Microsoft Teams" >}}

Se ha observado que el grupo de ransomware DragonForce utiliza un malware personalizado llamado 'Backdoor.Turn' para ocultar su tráfico de comando y control (C2) dentro de la infraestructura de retransmisión de Microsoft Teams. Esta técnica permite a los atacantes mezclar comunicaciones maliciosas con tráfico legítimo de Teams, dificultando la detección para los defensores de la red.

{{< ad-banner >}}

Al abusar de las retransmisiones de Microsoft Teams, la banda de ransomware puede eludir los controles de seguridad de red tradicionales que quizás no examinen el tráfico hacia servicios de confianza. El malware probablemente aprovecha las API o protocolos de Teams para tunelizar datos C2, evadiendo la detección basada en firmas y permitiendo acceso persistente a redes comprometidas.

Las organizaciones que utilizan Microsoft Teams deben monitorear patrones inusuales de tráfico saliente hacia los puntos finales de Teams y considerar la implementación de inspección adicional para túneles cifrados. Este incidente resalta la creciente tendencia de los grupos de ransomware a adoptar técnicas de 'vivir de la tierra' y abuso de servicios de confianza para evadir la detección.

{{< netrunner-insight >}}

Para los analistas del SOC, esto subraya la necesidad de establecer una línea base del tráfico normal de Teams y alertar sobre anomalías como volúmenes de datos inesperados o conexiones a puntos finales de Teams no estándar. Los equipos de DevSecOps deben revisar los permisos de integración de Teams y restringir el acceso innecesario a las API para reducir la superficie de ataque para el abuso de retransmisión.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
