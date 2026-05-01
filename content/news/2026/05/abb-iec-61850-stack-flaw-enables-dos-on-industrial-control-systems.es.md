---
title: "Fallo en la pila IEC 61850 de ABB permite denegación de servicio en sistemas de control industrial"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "es"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre una vulnerabilidad reportada de forma privada en la implementación de IEC 61850 MMS de ABB que afecta a los productos System 800xA y Symphony Plus, provocando fallos en los dispositivos y denegación de servicio."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre una vulnerabilidad reportada de forma privada en la implementación de IEC 61850 MMS de ABB que afecta a los productos System 800xA y Symphony Plus, provocando fallos en los dispositivos y denegación de servicio.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA ha emitido un aviso (ICSA-26-120-01) sobre una vulnerabilidad en la implementación de ABB de la pila de comunicación IEC 61850 para aplicaciones cliente MMS. El fallo afecta a múltiples productos de las líneas System 800xA y Symphony Plus, incluyendo AC800M CI868, Symphony Plus SD Series CI850, PM 877 y S+ Operations. La explotación requiere acceso previo a la red IEC 61850 del sitio.

{{< ad-banner >}}

Una explotación exitosa provoca un fallo del dispositivo en los módulos PM 877, CI850 y CI868, lo que requiere un reinicio manual. Para los nodos S+ Operations, el ataque bloquea el controlador de comunicación IEC 61850, lo que lleva a una condición de denegación de servicio si se repite. Sin embargo, la disponibilidad y funcionalidad general del nodo no se ven afectadas, y la comunicación del protocolo GOOSE no se ve impactada. El System 800xA IEC61850 Connect tampoco es vulnerable.

Las versiones de firmware afectadas abarcan múltiples ramas, incluyendo S+ Operations hasta 6.2.0006.0 y varias versiones de PM 877. No se proporcionó un identificador CVE ni una puntuación CVSS en el aviso. Las organizaciones que utilizan estos productos deben revisar el aviso y aplicar mitigaciones, como la segmentación de red y los controles de acceso, para limitar la exposición a la red IEC 61850.

{{< netrunner-insight >}}

Esta vulnerabilidad subraya la importancia de la segmentación de red en entornos OT. Dado que la explotación requiere acceso a la red IEC 61850, aislar esa red de la TI corporativa e internet es crítico. Los analistas del SOC deben monitorear el tráfico IEC 61850 anómalo, mientras que los ingenieros de DevSecOps deben priorizar la aplicación de parches y considerar la implementación de detección de intrusiones para anomalías en el protocolo MMS.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
