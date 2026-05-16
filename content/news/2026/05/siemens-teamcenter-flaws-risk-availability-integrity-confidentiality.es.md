---
title: "Las fallas de Siemens Teamcenter comprometen disponibilidad, integridad y confidencialidad"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "es"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiples vulnerabilidades en Siemens Teamcenter podrían comprometer la disponibilidad, integridad y confidencialidad. Actualice a las últimas versiones de inmediato."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiples vulnerabilidades en Siemens Teamcenter podrían comprometer la disponibilidad, integridad y confidencialidad. Actualice a las últimas versiones de inmediato.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

Siemens Teamcenter está afectado por múltiples vulnerabilidades que podrían llevar al compromiso de la disponibilidad, integridad y confidencialidad. Las fallas incluyen una verificación incorrecta de condiciones inusuales o excepcionales, cross-site scripting y uso de credenciales codificadas. Las versiones afectadas incluyen Teamcenter V2312, V2406, V2412, V2506 y V2512.

{{< ad-banner >}}

CVE-2024-4367 es una verificación de tipo faltante al manejar fuentes en PDF.js, lo que permite la ejecución arbitraria de JavaScript en el contexto de PDF.js. Esta vulnerabilidad afecta a Firefox y Thunderbird, pero está listada en el aviso de Siemens. Siemens recomienda actualizar a las últimas versiones de Teamcenter para mitigar estos riesgos.

Las vulnerabilidades tienen una puntuación base CVSS v3 de 7.5, lo que indica una severidad alta. Los sectores críticos de fabricación están afectados, con despliegue mundial. Las organizaciones deben priorizar el parcheo y revisar su exposición a estas vulnerabilidades.

{{< netrunner-insight >}}

Los analistas del SOC deben inventariar de inmediato todas las instancias de Teamcenter y priorizar el parcheo a las últimas versiones. Los equipos de DevSecOps deben verificar que los componentes de PDF.js estén actualizados y monitorear intentos de explotación dirigidos a estos CVE. Dada la alta puntuación CVSS y el potencial de compromiso total, trate esto como una remediación de alta prioridad.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
