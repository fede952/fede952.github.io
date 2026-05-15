---
title: "Fallos en Siemens Ruggedcom ROX: Actualice a la v2.17.1 Ahora"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "es"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre múltiples vulnerabilidades de terceros en Siemens Ruggedcom ROX anteriores a v2.17.1. Se enumeran más de 30 CVE, incluidos riesgos de ejecución remota de código. Se recomienda una actualización inmediata."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Dispositivos Siemens Ruggedcom ROX"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre múltiples vulnerabilidades de terceros en Siemens Ruggedcom ROX anteriores a v2.17.1. Se enumeran más de 30 CVE, incluidos riesgos de ejecución remota de código. Se recomienda una actualización inmediata.

{{< cyber-report severity="High" source="CISA" target="Dispositivos Siemens Ruggedcom ROX" cve="CVE-2019-13103" >}}

Las versiones de Siemens Ruggedcom ROX anteriores a 2.17.1 contienen múltiples vulnerabilidades de terceros, según lo divulgado en el aviso ICSA-26-134-16 de CISA. Los productos afectados incluyen las series RUGGEDCOM ROX MX5000, MX5000RE y RX1400. Siemens ha lanzado versiones actualizadas para solucionar estos problemas y recomienda encarecidamente actualizar a la última versión.

{{< ad-banner >}}

El aviso enumera más de 30 CVE que abarcan desde 2019 hasta 2025, incluyendo CVE-2019-13103, CVE-2022-2347 y CVE-2025-0395. Aunque no se proporcionan puntuaciones CVSS específicas, la amplitud y antigüedad de las vulnerabilidades sugieren una superficie de ataque significativa. Muchos de estos CVE están asociados con componentes de terceros y podrían provocar ejecución remota de código, denegación de servicio o divulgación de información.

Las organizaciones que utilicen dispositivos Ruggedcom ROX afectados deben priorizar la aplicación de parches, especialmente si los dispositivos están expuestos a redes no confiables. Dada la naturaleza industrial de estos productos, los sistemas sin parchear podrían ser aprovechados para movimiento lateral o interrupción de infraestructuras críticas.

{{< netrunner-insight >}}

Este es un caso clásico de deuda técnica acumulada en sistemas embebidos. Los equipos de SOC deben inventariar todas las instancias de Ruggedcom ROX y verificar las versiones de firmware. Los equipos de DevSecOps deben integrar el escaneo automatizado de CVE en su CI/CD para dependencias de terceros. La falta de puntuaciones CVSS es preocupante: asuma el peor caso y trátelos como críticos hasta que se demuestre lo contrario.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
