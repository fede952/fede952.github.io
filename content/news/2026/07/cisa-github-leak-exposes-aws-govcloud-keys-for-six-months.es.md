---
title: "Filtración en GitHub de CISA expone claves de AWS GovCloud durante seis meses"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "es"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "Un contratista filtró credenciales internas de CISA, incluyendo claves de AWS GovCloud, en GitHub durante seis meses. Expertos destacan lecciones críticas para los equipos de seguridad."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "Repositorio de GitHub de CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un contratista filtró credenciales internas de CISA, incluyendo claves de AWS GovCloud, en GitHub durante seis meses. Expertos destacan lecciones críticas para los equipos de seguridad.

{{< cyber-report severity="High" source="Krebs on Security" target="Repositorio de GitHub de CISA" >}}

La Agencia de Seguridad de Ciberseguridad e Infraestructura (CISA) reveló una filtración de datos en la que un contratista publicó inadvertidamente docenas de credenciales internas, incluyendo claves de AWS GovCloud, en un repositorio público de GitHub. Las credenciales permanecieron expuestas durante casi seis meses antes de que KrebsOnSecurity notificara a la agencia.

{{< ad-banner >}}

El análisis posterior de CISA identificó brechas en su respuesta inicial, como detección tardía y falta de escaneo automatizado de secretos en repositorios públicos. El incidente subraya la necesidad de una gestión robusta de secretos y monitoreo continuo de repositorios de código.

Los expertos recomiendan implementar hooks de pre-commit, escaneo regular de secretos y controles de acceso estrictos para prevenir filtraciones similares. El uso de credenciales efímeras y rotación automatizada también puede mitigar el impacto de claves expuestas.

{{< netrunner-insight >}}

Este incidente es un caso de libro de por qué el escaneo de secretos debe integrarse en los pipelines de CI/CD, no solo después del commit. Los analistas del SOC deben priorizar alertas sobre exposiciones en repositorios públicos, y los equipos de DevSecOps deben imponer acceso de mínimo privilegio para contratistas. Automatice la rotación de credenciales y considere usar herramientas como GitLeaks o TruffleHog para detectar filtraciones temprano.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
