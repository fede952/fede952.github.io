---
title: "PCs industriales ABB B&R afectados por múltiples CVE: RCE, DoS, envenenamiento de DNS"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "es"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre vulnerabilidades en PCs industriales ABB B&R. Hay una actualización disponible. Los atacantes pueden lograr ejecución remota de código, DoS, envenenamiento de caché DNS o robo de datos."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "PCs industriales ABB B&R"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre vulnerabilidades en PCs industriales ABB B&R. Hay una actualización disponible. Los atacantes pueden lograr ejecución remota de código, DoS, envenenamiento de caché DNS o robo de datos.

{{< cyber-report severity="High" source="CISA" target="PCs industriales ABB B&R" cve="CVE-2023-45229" >}}

ABB ha divulgado vulnerabilidades que afectan a múltiples líneas de productos de PC industriales B&R, incluyendo APC4100, APC910, C80, MPC3100, PPC1200, PPC900 y APC2200. Las fallas, registradas como CVE-2023-45229 a CVE-2023-45237, permiten a atacantes basados en red ejecutar código remoto, lanzar ataques de denegación de servicio, envenenar cachés DNS o extraer información sensible.

{{< ad-banner >}}

El aviso enumera las versiones afectadas para cada producto, con actualizaciones disponibles para remediar los problemas. Por ejemplo, las versiones de APC4100 inferiores a 1.09 son vulnerables, mientras que la versión 1.09 está parcheada. De manera similar, las versiones de APC910 hasta la 1.25 inclusive están afectadas. ABB recomienda actualizar inmediatamente a las últimas versiones de firmware.

Dado el contexto de sistemas de control industrial (ICS), estas vulnerabilidades representan riesgos significativos para los entornos de tecnología operativa. Las organizaciones que utilicen PCs ABB B&R afectados deben priorizar el parcheo, especialmente si los dispositivos están expuestos a redes no confiables.

{{< netrunner-insight >}}

Para los analistas de SOC, monitoreen el tráfico de red en busca de consultas DNS anómalas o conexiones inesperadas desde PCs B&R. Los equipos de DevSecOps deben inventariar todos los dispositivos afectados y aplicar las actualizaciones de firmware lo antes posible, ya que estos CVE permiten ejecución remota de código sin autenticación. Consideren segmentar las redes ICS para limitar la exposición.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
