---
title: "Las vulnerabilidades de ABB B&R Automation Studio exponen los ICS a ejecución remota de código"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "es"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte de 25 vulnerabilidades en ABB B&R Automation Studio, incluyendo fallos críticos con CVSS 9.8 que podrían permitir acceso no autorizado y ejecución remota de código."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte de 25 vulnerabilidades en ABB B&R Automation Studio, incluyendo fallos críticos con CVSS 9.8 que podrían permitir acceso no autorizado y ejecución remota de código.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA ha publicado un aviso que detalla múltiples vulnerabilidades en ABB B&R Automation Studio, que afectan a versiones anteriores a la 6.5 y a la versión 6.5. El aviso enumera 25 CVE, incluyendo CVE-2025-6965, CVE-2025-3277 y CVE-2023-7104, entre otros. Estas vulnerabilidades se originan en componentes de terceros desactualizados e incluyen problemas como desbordamientos de búfer en el montón, escrituras fuera de los límites, uso después de liberación y validación de entrada incorrecta.

{{< ad-banner >}}

Si bien ABB no reporta explotación observada durante las pruebas, las vulnerabilidades podrían presentar vectores de ataque para acceso no autorizado, exposición de datos o ejecución remota de código. Los CVE más graves tienen una puntuación CVSS v3 de 9.8, lo que indica una gravedad crítica. Los productos afectados se utilizan en sistemas de automatización y control industrial, lo que los convierte en objetivos atractivos para los actores de amenazas.

ABB ha lanzado una actualización que reemplaza el componente de terceros desactualizado. Se insta a las organizaciones que utilizan B&R Automation Studio a aplicar la actualización de inmediato. Dada la naturaleza crítica de estas vulnerabilidades y el potencial de explotación remota, los propietarios de activos deben priorizar la aplicación de parches y monitorear cualquier señal de compromiso.

{{< netrunner-insight >}}

Para los analistas de SOC y los ingenieros de DevSecOps, este aviso subraya el riesgo de las dependencias de terceros en el software ICS. El gran número de CVE (25) sugiere un problema sistémico con la gestión de componentes. Priorice el inventario de instancias de B&R Automation Studio y aplique la actualización del proveedor. Además, segmente las redes ICS para limitar la exposición e implemente monitoreo de comportamientos anómalos que puedan indicar intentos de explotación.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
