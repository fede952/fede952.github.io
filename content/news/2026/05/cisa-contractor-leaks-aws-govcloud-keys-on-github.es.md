---
title: "Contratista de CISA filtra claves de AWS GovCloud en GitHub"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "es"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "Un contratista de CISA expuso credenciales de AWS GovCloud y detalles internos de compilación en un repositorio público de GitHub, marcando una de las filtraciones de datos gubernamentales más graves."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "cuentas de AWS GovCloud de CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un contratista de CISA expuso credenciales de AWS GovCloud y detalles internos de compilación en un repositorio público de GitHub, marcando una de las filtraciones de datos gubernamentales más graves.

{{< cyber-report severity="Critical" source="Krebs on Security" target="cuentas de AWS GovCloud de CISA" >}}

Hasta el pasado fin de semana, un contratista de la Agencia de Seguridad de Infraestructura y Ciberseguridad (CISA) mantenía un repositorio público de GitHub que exponía credenciales de varias cuentas de AWS GovCloud con altos privilegios y una gran cantidad de sistemas internos de CISA. Expertos en seguridad afirmaron que el archivo público incluía documentos que detallan cómo CISA construye, prueba e implementa software internamente, y que representa una de las filtraciones de datos gubernamentales más flagrantes en la historia reciente.

{{< ad-banner >}}

Las credenciales expuestas podrían permitir a un atacante acceder a entornos gubernamentales sensibles en la nube y sistemas internos, lo que podría llevar a la exfiltración de datos o a un mayor compromiso. El incidente subraya los riesgos de tener secretos codificados en repositorios públicos, incluso por parte de contratistas gubernamentales.

{{< netrunner-insight >}}

Esta filtración resalta la necesidad crítica de escaneo automatizado de secretos y controles estrictos de acceso a repositorios. Los analistas del SOC deben priorizar la monitorización de credenciales expuestas en repositorios de código público, mientras que los equipos de DevSecOps deben aplicar políticas de gestión de secretos y rotar inmediatamente cualquier clave potencialmente comprometida.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en Krebs on Security ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
