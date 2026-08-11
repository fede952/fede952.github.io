---
title: "Ataque a la cadena de suministro de BdThemes crea administradores de WordPress no autorizados"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "es"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "El compromiso de la cadena de suministro afecta a los plugins de WordPress de BdThemes; no se modificó ningún código fuente, pero un JSON malicioso crea cuentas de administrador no autorizadas."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "Sitios de WordPress que utilizan plugins de BdThemes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El compromiso de la cadena de suministro afecta a los plugins de WordPress de BdThemes; no se modificó ningún código fuente, pero un JSON malicioso crea cuentas de administrador no autorizadas.

{{< cyber-report severity="High" source="The Hacker News" target="Sitios de WordPress que utilizan plugins de BdThemes" >}}

Investigadores de ciberseguridad han revelado un ataque a la cadena de suministro dirigido a BdThemes, un proveedor de plugins de WordPress. El compromiso provocó la desactivación temporal de las descargas de plugins por parte del equipo de plugins de WordPress. Cabe destacar que el ataque se desvía de los incidentes típicos de cadena de suministro: no se modificó ningún archivo de código fuente en el repositorio oficial de WordPress.org.

{{< ad-banner >}}

En su lugar, el ataque aprovecha cargas útiles JSON maliciosas para crear cuentas de administrador de WordPress no autorizadas. Esta técnica permite a los atacantes obtener acceso no autorizado a los sitios afectados sin alterar los archivos principales del plugin, lo que dificulta la detección mediante comprobaciones de integridad estándar.

El investigador de Wordfence, Paolo Tresso, destacó la naturaleza inusual del ataque, enfatizando que la ausencia de modificaciones en el código fuente subraya la necesidad de una monitorización integral de la cadena de suministro más allá de la integridad del código.

{{< netrunner-insight >}}

Este ataque subraya la importancia de monitorear no solo los cambios en el código, sino también los archivos de configuración y datos como JSON. Para los analistas de SOC, traten las actualizaciones de plugins como eventos de alto riesgo y verifiquen la integridad de todos los archivos, no solo del código fuente. DevSecOps debería implementar monitoreo en tiempo de ejecución para la creación inesperada de cuentas de administrador y considerar el monitoreo de integridad de archivos que cubra activos que no son código.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
