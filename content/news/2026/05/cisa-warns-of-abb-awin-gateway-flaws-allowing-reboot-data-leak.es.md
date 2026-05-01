---
title: "CISA advierte sobre fallas en puertas de enlace ABB AWIN que permiten reinicio y fuga de datos"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "Las puertas de enlace ABB AWIN tienen vulnerabilidades que permiten a atacantes reiniciar dispositivos o extraer configuración del sistema. El aviso de CISA ICSA-26-120-05 detalla CVE-2025-13777 y las correcciones."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "Puertas de enlace ABB AWIN"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Las puertas de enlace ABB AWIN tienen vulnerabilidades que permiten a atacantes reiniciar dispositivos o extraer configuración del sistema. El aviso de CISA ICSA-26-120-05 detalla CVE-2025-13777 y las correcciones.

{{< cyber-report severity="High" source="CISA" target="Puertas de enlace ABB AWIN" cve="CVE-2025-13777" cvss="8.3" >}}

CISA ha publicado el aviso ICSA-26-120-05 que detalla múltiples vulnerabilidades en las puertas de enlace ABB AWIN. Las fallas, que incluyen omisión de autenticación mediante captura-reproducción y falta de autenticación para funciones críticas, podrían permitir que un atacante no autenticado reinicie remotamente el dispositivo o consulte datos sensibles de configuración del sistema. Las vulnerabilidades afectan las versiones de firmware AWIN 2.0-0, 2.0-1, 1.2-0 y 1.2-1 que se ejecutan en hardware GW100 rev.2 y GW120.

{{< ad-banner >}}

El problema más grave, registrado como CVE-2025-13777, permite que una consulta no autenticada revele la configuración del sistema, incluidos detalles sensibles. El aviso asigna una puntuación base CVSS v3 de 8.3, lo que indica alta gravedad. ABB ha lanzado la versión de firmware 2.1-0 para GW100 rev.2 para remediar estas vulnerabilidades. Se insta a las organizaciones que utilizan puertas de enlace afectadas a aplicar la actualización de inmediato.

Las vulnerabilidades afectan activos del sector de fabricación crítica desplegados en todo el mundo. Dado el potencial de explotación remota sin autenticación, estas fallas representan un riesgo significativo para los entornos de tecnología operativa. CISA recomienda que los usuarios revisen el aviso completo e implementen mitigaciones, incluida la segmentación de red y la restricción del acceso a los dispositivos afectados.

{{< netrunner-insight >}}

Para analistas de SOC: monitoreen reinicios no autorizados o consultas inusuales a puertas de enlace ABB; estos son indicadores de bajo ruido de explotación. Los equipos de DevSecOps deben priorizar la actualización al firmware 2.1-0 y aplicar controles estrictos de acceso a la red, ya que las vulnerabilidades no requieren autenticación y pueden explotarse de forma remota.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
