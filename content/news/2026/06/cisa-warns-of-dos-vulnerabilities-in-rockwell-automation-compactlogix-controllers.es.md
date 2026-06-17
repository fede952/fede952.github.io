---
title: "CISA advierte sobre vulnerabilidades de denegación de servicio en controladores Rockwell Automation CompactLogix"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiples vulnerabilidades en los controladores Rockwell Automation CompactLogix 5370 podrían permitir ataques de denegación de servicio. CVE-2025-11694 se encuentra entre las fallas."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "controladores Rockwell Automation CompactLogix 5370"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiples vulnerabilidades en los controladores Rockwell Automation CompactLogix 5370 podrían permitir ataques de denegación de servicio. CVE-2025-11694 se encuentra entre las fallas.

{{< cyber-report severity="High" source="CISA" target="controladores Rockwell Automation CompactLogix 5370" cve="CVE-2025-11694" cvss="7.5" >}}

CISA ha publicado un aviso (ICSA-26-167-04) que detalla vulnerabilidades en los controladores Rockwell Automation CompactLogix 5370 (L1, L2, L3). Las fallas incluyen una validación incorrecta de los valores de integridad y la exposición de información sensible del sistema, lo que podría permitir a un atacante causar una condición de denegación de servicio. El aviso afecta a versiones anteriores a V38.011.

{{< ad-banner >}}

La vulnerabilidad más notable, CVE-2025-11694, implica la falta de validación de números de secuencia y direcciones IP de origen en el protocolo CIP. Un atacante puede explotar los ID de conexión expuestos visibles en la interfaz web para realizar ataques de denegación de servicio, lo que resulta en una falla menor. La puntuación CVSS v3 para esta vulnerabilidad es 7.5.

Rockwell Automation recomienda actualizar a la versión V38.011 para solucionar estos problemas. Los productos afectados se implementan en todo el mundo en el sector de fabricación crítica. Las organizaciones deben priorizar la aplicación de parches a estos controladores para mitigar posibles interrupciones operativas.

{{< netrunner-insight >}}

Para los analistas de SOC, monitoree patrones de tráfico CIP inusuales o intentos de conexión repetidos dirigidos a controladores CompactLogix. Los ingenieros de DevSecOps deben asegurarse de que la interfaz web no esté expuesta a redes no confiables y aplicar la actualización de firmware a V38.011 de inmediato. Este es un vector de denegación de servicio directo que se puede mitigar con una segmentación de red adecuada y una gestión de parches.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
