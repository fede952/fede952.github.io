---
title: "Vulnerabilidades en ABB Terra AC Wallbox permiten ejecución remota de código"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "es"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre desbordamientos de búfer en el montón y la pila en ABB Terra AC Wallbox (JP) ≤1.8.33; actualice a 1.8.36 para mitigar CVE-2025-10504, CVE-2025-12142, CVE-2025-12143."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre desbordamientos de búfer en el montón y la pila en ABB Terra AC Wallbox (JP) ≤1.8.33; actualice a 1.8.36 para mitigar CVE-2025-10504, CVE-2025-12142, CVE-2025-12143.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB ha revelado múltiples vulnerabilidades que afectan su línea de productos Terra AC Wallbox (JP), específicamente las versiones hasta la 1.8.33 inclusive. Las fallas incluyen un desbordamiento de búfer en el montón (CVE-2025-10504), una copia de búfer sin verificar el tamaño de entrada (CVE-2025-12142) y un desbordamiento de búfer en la pila (CVE-2025-12143). La explotación exitosa podría permitir a un atacante corromper la memoria del montón, lo que podría llevar al control remoto del dispositivo y escrituras no autorizadas en la memoria flash, alterando así el comportamiento del firmware.

{{< ad-banner >}}

Las vulnerabilidades tienen una puntuación base CVSS v3 de 6.1, lo que indica una gravedad media. ABB ha lanzado la versión de firmware 1.8.36 para solucionar estos problemas. Los productos se implementan en todo el mundo en el sector energético, y el proveedor recomienda aplicar la actualización lo antes posible.

Si bien no se ha reportado explotación activa, el potencial de ejecución remota de código y manipulación del firmware hace que estas vulnerabilidades sean críticas para los operadores de infraestructura de carga de vehículos eléctricos. Las organizaciones deben priorizar el parcheo de los dispositivos afectados, especialmente aquellos expuestos a redes no confiables.

{{< netrunner-insight >}}

Para los analistas de SOC, monitoree el tráfico anómalo hacia los dispositivos Terra AC Wallbox, especialmente operaciones de escritura inesperadas en la memoria flash. Los ingenieros de DevSecOps deben aplicar una validación estricta de entrada en cualquier protocolo personalizado que se comunique con el cargador y asegurarse de que las actualizaciones de firmware se apliquen rápidamente. Dada la puntuación CVSS de 6.1, trate estas como de prioridad media pero con alto impacto potencial debido al rol del dispositivo en infraestructura energética crítica.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
