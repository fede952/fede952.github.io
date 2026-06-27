---
title: "CISA agrega falla de RCE en PTC Windchill a KEV en medio de ataques activos de web shells"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "es"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA agrega una vulnerabilidad crítica de ejecución remota de código en PTC Windchill PDMlink y FlexPLM a su catálogo de Vulnerabilidades Explotadas Conocidas debido a explotación activa."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink y FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA agrega una vulnerabilidad crítica de ejecución remota de código en PTC Windchill PDMlink y FlexPLM a su catálogo de Vulnerabilidades Explotadas Conocidas debido a explotación activa.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink y FlexPLM" kev="true" >}}

La Agencia de Seguridad de Infraestructura y Ciberseguridad de EE. UU. (CISA) ha agregado una vulnerabilidad crítica de ejecución remota de código que afecta a PTC Windchill PDMlink y PTC FlexPLM a su catálogo de Vulnerabilidades Explotadas Conocidas (KEV). La decisión sigue a evidencia de explotación activa, con informes que indican ataques continuos de web shells dirigidos a estos sistemas empresariales de Gestión de Datos de Producto (PDM) y Gestión del Ciclo de Vida del Producto (PLM).

{{< ad-banner >}}

Aunque el identificador CVE específico no fue revelado en el anuncio, la vulnerabilidad se describe como una falla crítica de RCE que podría permitir a los atacantes ejecutar código arbitrario en los sistemas afectados. Se insta a las organizaciones que utilizan estos productos a priorizar la aplicación de parches y revisar sus entornos en busca de signos de compromiso, ya que la explotación puede llevar a la toma total del sistema.

El catálogo KEV de CISA sirve como una directiva operativa vinculante para las agencias federales, que requiere remediación dentro de plazos específicos. Se recomienda encarecidamente a las organizaciones del sector privado que traten esto como una amenaza de alta prioridad e implementen mitigaciones como la segmentación de red y la monitorización de actividad anómala de web shells.

{{< netrunner-insight >}}

Para los analistas de SOC, priorice la búsqueda de indicadores de web shells en servidores Windchill expuestos: busque procesos hijo inusuales generados por la aplicación o conexiones salientes a IPs desconocidas. Los equipos de DevSecOps deben aplicar inmediatamente los parches disponibles y considerar la implementación de parches virtuales o reglas de WAF si el parcheo se retrasa. Este es un recordatorio de que los sistemas PLM, a menudo pasados por alto en la gestión de parches, son objetivos atractivos para los grupos de ransomware.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
