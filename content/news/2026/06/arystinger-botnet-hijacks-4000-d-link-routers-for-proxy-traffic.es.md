---
title: "La botnet AryStinger secuestra más de 4,000 routers D-Link para tráfico proxy"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "es"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nueva botnet llamada AryStinger ha comprometido más de 4,000 routers D-Link desactualizados, convirtiéndolos en proxies para tráfico malicioso. No hay datos de CVE o CVSS disponibles."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "Routers D-Link desactualizados"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nueva botnet llamada AryStinger ha comprometido más de 4,000 routers D-Link desactualizados, convirtiéndolos en proxies para tráfico malicioso. No hay datos de CVE o CVSS disponibles.

{{< cyber-report severity="Medium" source="BleepingComputer" target="Routers D-Link desactualizados" >}}

Una botnet de malware no documentada anteriormente llamada AryStinger ha comprometido más de 4,000 routers D-Link desactualizados en todo el mundo, según un informe de BleepingComputer. La botnet convierte estos dispositivos en proxies para tráfico malicioso, permitiendo a los atacantes anonimizar sus actividades y potencialmente lanzar más ataques.

{{< ad-banner >}}

Se cree que los routers comprometidos ejecutan firmware desactualizado con vulnerabilidades conocidas, aunque no se revelaron identificadores CVE específicos en el informe. La infraestructura y los métodos de propagación de la botnet aún están bajo análisis, pero la escala de la infección resalta los riesgos que plantean los dispositivos IoT sin parches.

Se recomienda a las organizaciones inventariar sus dispositivos de red, asegurarse de que el firmware esté actualizado y monitorear patrones de tráfico inusuales que puedan indicar uso de proxy. La falta de indicadores técnicos detallados en el informe inicial sugiere que se necesita más investigación para desarrollar firmas de detección.

{{< netrunner-insight >}}

Para los analistas de SOC, esto es un recordatorio de monitorear conexiones salientes inesperadas desde dispositivos de red, especialmente routers antiguos. Los equipos de DevSecOps deben aplicar políticas de actualización de firmware y considerar segmentar los dispositivos IoT de las redes críticas. Sin IoCs específicos, el análisis de tráfico de referencia y la identificación de dispositivos son clave para detectar dicha actividad de botnet.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
