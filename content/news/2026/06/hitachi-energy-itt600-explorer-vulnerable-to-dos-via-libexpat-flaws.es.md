---
title: "Hitachi Energy ITT600 Explorer vulnerable a DoS por fallos en libexpat"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "es"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte de dos vulnerabilidades en Hitachi Energy ITT600 Explorer que podrían permitir ataques de denegación de servicio. Afecta a versiones anteriores a 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte de dos vulnerabilidades en Hitachi Energy ITT600 Explorer que podrían permitir ataques de denegación de servicio. Afecta a versiones anteriores a 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

Hitachi Energy ha revelado vulnerabilidades en su producto ITT600 Explorer, que afectan específicamente a versiones anteriores a 2.1 SP6. Los fallos, identificados como CVE-2024-8176 y CVE-2025-59375, implican recursión sin control y asignación de recursos sin límites o restricciones. Estos problemas pueden ser explotados para causar una condición de denegación de servicio (DoS).

{{< ad-banner >}}

Las vulnerabilidades residen en la biblioteca libexpat utilizada por la funcionalidad IEC61850. Un atacante con acceso local podría enviar un mensaje IEC61850 manipulado para desencadenar un desbordamiento de pila, lo que podría provocar corrupción de memoria además de DoS. Es importante destacar que solo el producto ITT600 Explorer se ve afectado; los endpoints del sistema IEC 61850 permanecen sin afectar.

CISA recomienda tomar medidas inmediatas para aplicar mitigaciones o actualizaciones. El producto está implementado en todo el mundo en el sector energético, y su explotación podría interrumpir operaciones de infraestructura crítica. Las organizaciones que utilicen versiones afectadas deben priorizar la aplicación de parches y revisar el aviso para obtener pasos detallados de remediación.

{{< netrunner-insight >}}

Para los analistas del SOC, monitoreen patrones inusuales de tráfico IEC61850 que puedan indicar intentos de explotación. Los equipos de DevSecOps deben priorizar la actualización de ITT600 Explorer a la versión 2.1 SP6 o posterior, y considerar la segmentación de red para limitar el acceso local a la herramienta. Dado el puntaje CVSS de 7.5 y el potencial de corrupción de memoria, traten esto como un parche de alta prioridad.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
