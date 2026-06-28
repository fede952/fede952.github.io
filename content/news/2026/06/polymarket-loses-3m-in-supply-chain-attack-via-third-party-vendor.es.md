---
title: "Polymarket pierde $3M en un ataque a la cadena de suministro a través de un proveedor externo"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "es"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "Los hackers inyectaron un script malicioso en el frontend de Polymarket tras vulnerar a un proveedor externo, causando pérdidas de $3M a los clientes. La plataforma reembolsará completamente a las víctimas."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Usuarios del frontend de Polymarket"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Los hackers inyectaron un script malicioso en el frontend de Polymarket tras vulnerar a un proveedor externo, causando pérdidas de $3M a los clientes. La plataforma reembolsará completamente a las víctimas.

{{< cyber-report severity="High" source="BleepingComputer" target="Usuarios del frontend de Polymarket" >}}

Polymarket, una plataforma de predicción descentralizada, reveló que atacantes comprometieron a un proveedor externo para inyectar un script malicioso en su frontend, lo que resultó en una pérdida estimada de $3 millones para los clientes. El incidente, descrito como un ataque a la cadena de suministro, tuvo como objetivo la interfaz de usuario de la plataforma para desviar fondos.

{{< ad-banner >}}

La empresa declaró que reembolsará completamente a los clientes afectados, aunque el número exacto de víctimas no se ha revelado. La brecha subraya los riesgos asociados con las dependencias de terceros en plataformas DeFi y cripto, donde la integridad del frontend es crítica para la seguridad de las transacciones.

Si bien no se proporcionó ningún CVE o puntuación CVSS específica, el vector de ataque—comprometer a un proveedor para alterar el código del frontend—destaca la necesidad de medidas sólidas de seguridad en la cadena de suministro, como la firma de código, las comprobaciones de integridad y las evaluaciones de riesgos de proveedores.

{{< netrunner-insight >}}

Este incidente es un ataque clásico a la cadena de suministro dirigido a la integridad del frontend. Los analistas del SOC deben monitorear inyecciones de scripts no autorizadas en aplicaciones web, especialmente aquellas que dependen de bibliotecas o CDN de terceros. Los equipos de DevSecOps deben imponer políticas estrictas de seguridad de contenido (CSP), comprobaciones de integridad de subrecursos (SRI) y auditorías periódicas de proveedores para mitigar dichos riesgos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
