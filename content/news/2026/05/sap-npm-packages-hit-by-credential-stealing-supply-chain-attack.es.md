---
title: "Paquetes npm de SAP afectados por un ataque a la cadena de suministro que roba credenciales"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "es"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Una campaña denominada 'Mini Shai-Hulud' ataca paquetes npm relacionados con SAP con malware robacredenciales, afectando a múltiples paquetes. Investigadores de varias empresas advierten sobre los riesgos en la cadena de suministro."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "Paquetes npm relacionados con SAP"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una campaña denominada 'Mini Shai-Hulud' ataca paquetes npm relacionados con SAP con malware robacredenciales, afectando a múltiples paquetes. Investigadores de varias empresas advierten sobre los riesgos en la cadena de suministro.

{{< cyber-report severity="High" source="The Hacker News" target="Paquetes npm relacionados con SAP" >}}

Investigadores en ciberseguridad han descubierto una campaña de ataque a la cadena de suministro dirigida a paquetes npm relacionados con SAP. Denominada 'Mini Shai-Hulud', la campaña despliega malware robacredenciales a través de paquetes comprometidos, según informes de Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity y Wiz.

{{< ad-banner >}}

El ataque afecta a múltiples paquetes npm asociados con SAP, aunque no se han revelado nombres ni versiones específicas de los paquetes. El malware está diseñado para robar credenciales, lo que podría dar a los atacantes acceso a entornos SAP sensibles y sistemas posteriores.

Este incidente resalta la creciente amenaza a las cadenas de suministro de software, particularmente para plataformas críticas empresariales como SAP. Se recomienda a las organizaciones que utilicen paquetes afectados auditar sus dependencias y rotar cualquier credencial potencialmente comprometida.

{{< netrunner-insight >}}

Para los analistas de SOC y equipos DevSecOps, este ataque subraya la necesidad de un escaneo riguroso de dependencias y verificaciones de integridad en los paquetes npm. Monitoree conexiones salientes inusuales desde sistemas relacionados con SAP y considere implementar protección de aplicaciones en tiempo de ejecución (RASP) para detectar el robo de credenciales. Rote inmediatamente todas las credenciales que puedan haber quedado expuestas a través de paquetes comprometidos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
