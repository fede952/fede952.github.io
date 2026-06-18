---
title: "CISA advierte sobre una omisión crítica de autenticación en Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre CVE-2025-14272 que afecta a Rockwell Automation FactoryTalk Analytics PavilionX <7.01, permitiendo operaciones privilegiadas no autorizadas en entornos de fabricación críticos."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre CVE-2025-14272 que afecta a Rockwell Automation FactoryTalk Analytics PavilionX <7.01, permitiendo operaciones privilegiadas no autorizadas en entornos de fabricación críticos.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA ha publicado un aviso (ICSA-26-167-01) sobre una vulnerabilidad de falta de autorización en Rockwell Automation FactoryTalk Analytics PavilionX. La falla, registrada como CVE-2025-14272, afecta a versiones anteriores a la 7.01 y permite que un atacante no autorizado ejecute operaciones privilegiadas como la gestión de usuarios y roles.

{{< ad-banner >}}

La vulnerabilidad se origina por una aplicación incorrecta de la autorización en los endpoints de la API. Una explotación exitosa podría llevar al control administrativo total del sistema afectado. Rockwell Automation ha lanzado la versión 7.01 para solucionar el problema y se insta a los usuarios a actualizar de inmediato.

Dado el despliegue de este producto en sectores de fabricación críticos en todo el mundo, el riesgo de interrupción operativa o compromiso de datos es significativo. Las organizaciones deben priorizar la aplicación de parches y revisar los controles de acceso para mitigar una posible explotación.

{{< netrunner-insight >}}

Esta es una omisión de autorización clásica que debe tratarse como un parche de alta prioridad. Los analistas del SOC deben monitorear llamadas API anómalas o escaladas de privilegios en entornos PavilionX. Los equipos de DevSecOps deben asegurarse de que la versión 7.01 esté implementada y que la segmentación de la red limite la exposición de estos endpoints.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
