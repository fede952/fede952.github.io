---
title: "CISA advierte sobre la puerta trasera FIRESTARTER dirigida a dispositivos Cisco Firepower"
date: "2026-04-23T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA y NCSC alertan sobre actores APT que utilizan la puerta trasera FIRESTARTER para persistencia en dispositivos Cisco ASA/FTD. Se describen acciones de respuesta urgentes."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Dispositivos Cisco Firepower y Secure Firewall"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA y NCSC alertan sobre actores APT que utilizan la puerta trasera FIRESTARTER para persistencia en dispositivos Cisco ASA/FTD. Se describen acciones de respuesta urgentes.

{{< cyber-report severity="High" source="CISA" target="Dispositivos Cisco Firepower y Secure Firewall" >}}

CISA y el NCSC del Reino Unido han publicado un Informe de Análisis de Malware sobre la puerta trasera FIRESTARTER, que está siendo utilizada por actores de amenazas persistentes avanzadas (APT) para mantener persistencia en dispositivos Cisco Firepower y Secure Firewall accesibles públicamente que ejecutan software ASA o FTD. El análisis se basa en una muestra obtenida de una investigación forense, y CISA ha confirmado implantes exitosos en el mundo real en dispositivos Cisco Firepower con software ASA.

{{< ad-banner >}}

La publicación se alinea con la Directiva de Emergencia 25-03 de CISA, instando a las agencias FCEB de EE. UU. a recolectar y enviar volcados de núcleo a la plataforma Malware Next Generation de CISA e informar inmediatamente los envíos a través del Centro de Operaciones 24/7. Se recomienda a las organizaciones no tomar medidas adicionales hasta que CISA proporcione los próximos pasos.

Si bien el malware es relevante tanto para dispositivos Cisco Firepower como Secure Firewall, CISA solo ha observado implantes exitosos en dispositivos Firepower que ejecutan ASA. El informe enfatiza la necesidad de vigilancia y búsqueda proactiva de indicadores de compromiso.

{{< netrunner-insight >}}

Los analistas del SOC deben priorizar la recolección de volcados de núcleo de dispositivos Cisco ASA/FTD y enviarlos a CISA para su análisis. Los equipos de DevSecOps deben asegurarse de que los dispositivos Cisco estén parcheados y configurados según las mejores prácticas, y monitorear mecanismos de persistencia inusuales. Esta puerta trasera resalta la criticidad de asegurar los dispositivos de borde de red contra amenazas de nivel APT.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
