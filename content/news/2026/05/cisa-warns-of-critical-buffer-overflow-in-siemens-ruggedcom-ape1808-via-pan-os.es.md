---
title: "CISA Advierte sobre Desbordamiento de Búfer Crítico en Siemens RUGGEDCOM APE1808 a través de PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Un desbordamiento de búfer en el Portal Cautivo de Palo Alto Networks PAN-OS afecta a los dispositivos Siemens RUGGEDCOM APE1808. CVE-2026-0300 permite la ejecución remota de código no autenticado con privilegios de root."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Dispositivos Siemens RUGGEDCOM APE1808"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un desbordamiento de búfer en el Portal Cautivo de Palo Alto Networks PAN-OS afecta a los dispositivos Siemens RUGGEDCOM APE1808. CVE-2026-0300 permite la ejecución remota de código no autenticado con privilegios de root.

{{< cyber-report severity="Critical" source="CISA" target="Dispositivos Siemens RUGGEDCOM APE1808" cve="CVE-2026-0300" cvss="10.0" >}}

CISA ha publicado un aviso (ICSA-26-139-02) que detalla una vulnerabilidad crítica de desbordamiento de búfer en el servicio de Portal de Autenticación de ID de Usuario (Portal Cautivo) del software PAN-OS de Palo Alto Networks. Esta falla, registrada como CVE-2026-0300 con una puntuación CVSS de 10.0, permite que un atacante no autenticado ejecute código arbitrario con privilegios de root en firewalls de las series PA y VM mediante el envío de paquetes especialmente diseñados.

{{< ad-banner >}}

La vulnerabilidad afecta a los dispositivos Siemens RUGGEDCOM APE1808 que ejecutan todas las versiones. Siemens está preparando versiones de corrección y recomienda implementar las soluciones alternativas proporcionadas en las notificaciones de seguridad de Palo Alto Networks. Hasta que los parches estén disponibles, las organizaciones deben deshabilitar el servicio de Portal Cautivo si no es necesario y restringir el acceso de red a los dispositivos afectados.

Dada la puntuación CVSS crítica y el potencial de compromiso total del sistema, se justifica una acción inmediata. El aviso se dirige al sector de fabricación crítica, con dispositivos desplegados en todo el mundo. Los operadores deben priorizar la aplicación de mitigaciones y monitorear cualquier signo de explotación.

{{< netrunner-insight >}}

Este es un ejemplo clásico de riesgo en la cadena de suministro: un componente de terceros (PAN-OS) introduce una falla crítica en un producto industrial. Los analistas del SOC deben buscar inmediatamente tráfico anómalo hacia los puertos del Portal Cautivo y asegurarse de que la segmentación limite la exposición. Los equipos de DevSecOps deben inventariar todas las instancias de RUGGEDCOM APE1808 y aplicar las mitigaciones de Palo Alto Networks sin demora.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
