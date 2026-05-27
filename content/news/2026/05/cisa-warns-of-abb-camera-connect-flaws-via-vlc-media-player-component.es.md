---
title: "CISA Advierte sobre Fallos en ABB Camera Connect a través del Componente VLC Media Player"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect versiones ≤1.5.0.14 incluye un VLC media player 2.2.4 vulnerable con múltiples errores de corrupción de memoria, incluyendo CVE-2024-46461, lo que representa un riesgo crítico."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect versiones ≤1.5.0.14 incluye un VLC media player 2.2.4 vulnerable con múltiples errores de corrupción de memoria, incluyendo CVE-2024-46461, lo que representa un riesgo crítico.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA ha publicado un aviso (ICSA-26-146-05) que detalla múltiples vulnerabilidades en ABB Ability Camera Connect versiones 1.5.0.14 y anteriores. Las fallas se originan en un componente de terceros desactualizado, VLC media player versión 2.2.4, que se incluye con el paquete de instalación. Una actualización a la versión 1.5.0.15 resuelve el problema reemplazando el componente vulnerable.

{{< ad-banner >}}

Las vulnerabilidades incluyen desbordamiento de búfer basado en montón, desbordamiento de entero, escritura fuera de límites, elemento de ruta de búsqueda no controlado, desbordamiento de entero, error off-by-one, lectura fuera de límites, doble liberación, restricción inadecuada de operaciones en búferes de memoria y use-after-free. En particular, CVE-2024-46461 describe un desbordamiento basado en montón en VLC media player 3.0.20 y anteriores a través de un flujo MMS maliciosamente diseñado, lo que lleva a una denegación de servicio.

Con una puntuación CVSS v3 de 9.8, estas vulnerabilidades están clasificadas como Críticas. Los sectores de infraestructura crítica afectados incluyen Químico, Instalaciones Comerciales, Comunicaciones, Manufactura Crítica, Energía y Sistemas de Transporte. El producto se implementa a nivel mundial y la explotación podría permitir a un atacante comprometer el sistema de varias maneras.

{{< netrunner-insight >}}

Este aviso subraya el riesgo de vulnerabilidades heredadas de componentes de terceros. Los analistas del SOC deben priorizar la aplicación de parches en ABB Ability Camera Connect a la versión 1.5.0.15 y monitorear intentos de explotación dirigidos a fallas de VLC media player. Los equipos de DevSecOps deben imponer un control estricto de versiones de componentes y escaneo regular de bibliotecas incluidas.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
