---
title: "Vulnerabilidades en Hitachi Energy RTU500 permiten denegación de servicio, afectan disponibilidad"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "es"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre múltiples vulnerabilidades en la serie Hitachi Energy RTU500, incluyendo desreferencia de puntero NULL y bucle infinito, con CVSS 7.8. Se enumeran las versiones afectadas."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "Firmware CMU de la serie Hitachi Energy RTU500"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre múltiples vulnerabilidades en la serie Hitachi Energy RTU500, incluyendo desreferencia de puntero NULL y bucle infinito, con CVSS 7.8. Se enumeran las versiones afectadas.

{{< cyber-report severity="High" source="CISA" target="Firmware CMU de la serie Hitachi Energy RTU500" cve="CVE-2025-69421" cvss="7.8" >}}

Hitachi Energy ha revelado múltiples vulnerabilidades que afectan el firmware CMU de su serie RTU500. Las fallas incluyen desreferencia de puntero NULL, desbordamiento o envoltura de enteros, y bucle con condición de salida inalcanzable (bucle infinito), lo que podría provocar condiciones de denegación de servicio. La explotación afecta principalmente la disponibilidad del producto, con posibles efectos secundarios en la confidencialidad e integridad.

{{< ad-banner >}}

El aviso, publicado por CISA (ICSA-26-155-04), enumera las versiones de firmware afectadas desde 12.7.1 hasta 13.8.1. Se asocian múltiples CVE, incluyendo CVE-2025-69421, CVE-2026-24515, CVE-2026-25210, CVE-2026-32776, CVE-2026-32777, CVE-2026-32778 y CVE-2026-8479. Las vulnerabilidades tienen una puntuación base CVSS v3 de 7.8, lo que indica una alta gravedad.

Hitachi Energy recomienda tomar medidas inmediatas según las pautas de remediación del aviso. Dado el contexto de infraestructura crítica, las organizaciones que utilizan versiones afectadas de RTU500 deben priorizar la aplicación de parches e implementar segmentación de red para mitigar el riesgo de explotación.

{{< netrunner-insight >}}

Estas vulnerabilidades son un recordatorio de que los dispositivos OT suelen retrasarse en los ciclos de parches. Los equipos SOC deben monitorear el tráfico anómalo hacia las unidades RTU500 y asegurarse de que estos dispositivos estén aislados de redes no confiables. Los ingenieros DevSecOps deben integrar el escaneo de firmware en los pipelines CI/CD para detectar CVE conocidos antes de la implementación.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
