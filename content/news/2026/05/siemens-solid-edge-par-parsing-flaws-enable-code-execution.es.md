---
title: "Fallos en el análisis de archivos PAR de Siemens Solid Edge permiten ejecución de código"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "es"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Dos vulnerabilidades de análisis de archivos en Siemens Solid Edge SE2026 permiten a atacantes ejecutar código arbitrario mediante archivos PAR especialmente diseñados. Actualice a V226.0 Update 5."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Dos vulnerabilidades de análisis de archivos en Siemens Solid Edge SE2026 permiten a atacantes ejecutar código arbitrario mediante archivos PAR especialmente diseñados. Actualice a V226.0 Update 5.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

Siemens Solid Edge SE2026 anterior a Update 5 está afectado por dos vulnerabilidades de análisis de archivos que pueden activarse cuando la aplicación lee archivos PAR especialmente diseñados. Los fallos incluyen un acceso a puntero no inicializado (CVE-2026-44411) y un desbordamiento de búfer basado en pila (CVE-2026-44412), ambos podrían permitir a un atacante bloquear la aplicación o ejecutar código arbitrario en el contexto del proceso actual.

{{< ad-banner >}}

Las vulnerabilidades tienen una puntuación base CVSS v3.1 de 7.8 (Alta) con el vector AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, lo que indica acceso local, baja complejidad, sin privilegios requeridos, interacción del usuario necesaria y alto impacto en confidencialidad, integridad y disponibilidad. Siemens ha lanzado la versión V226.0 Update 5 para solucionar estos problemas y recomienda a los usuarios actualizar inmediatamente.

Dado el despliegue en el sector de fabricación crítica a nivel mundial, las organizaciones que utilizan Solid Edge deberían priorizar la aplicación de parches. Las vulnerabilidades requieren interacción del usuario (abrir un archivo PAR malicioso), por lo que también se recomienda la capacitación en concienciación de usuarios como control compensatorio.

{{< netrunner-insight >}}

Para los analistas del SOC, monitorear el manejo inusual de archivos PAR o bloqueos en procesos de Solid Edge. Los ingenieros de DevSecOps deben aplicar listas blancas de aplicaciones y restringir tipos de archivo para reducir la superficie de ataque. Dado que son vulnerabilidades locales que dependen de la interacción del usuario, las simulaciones de phishing y las reglas de detección de endpoints para aperturas de archivos sospechosas son mitigaciones clave.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
