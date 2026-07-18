---
title: "Subgrupo GoldenEyeDog vinculado a la brecha de DigiCert y robo de firmas de código"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "es"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Investigadores atribuyen el incidente de DigiCert de abril de 2026 a CylindricalCanine, un subgrupo del grupo de ciberdelincuencia china GoldenEyeDog, conocido por atacar los sectores de juegos de azar y videojuegos."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "Infraestructura de firma de código de DigiCert"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Investigadores atribuyen el incidente de DigiCert de abril de 2026 a CylindricalCanine, un subgrupo del grupo de ciberdelincuencia china GoldenEyeDog, conocido por atacar los sectores de juegos de azar y videojuegos.

{{< cyber-report severity="High" source="The Hacker News" target="Infraestructura de firma de código de DigiCert" >}}

Investigadores en ciberseguridad han atribuido el incidente de seguridad de abril de 2026 en DigiCert a un grupo de actividad de amenazas denominado CylindricalCanine. El grupo se describe como un subgrupo de GoldenEyeDog (también conocido como APT-Q-27, Dragon Breath y Miuuti Group), un grupo de ciberdelincuencia china que históricamente ataca los sectores de juegos de azar y videojuegos.

{{< ad-banner >}}

La brecha implicó el robo de certificados de firma de código, lo que podría permitir a los actores de amenazas firmar software malicioso con credenciales legítimas, eludiendo los controles de seguridad. Expel compartió detalles técnicos del evento, destacando la naturaleza sofisticada de la operación.

Las organizaciones que dependen de certificados emitidos por DigiCert deben revisar sus inventarios de certificados y monitorear cualquier uso no autorizado. El incidente subraya los riesgos que plantean los ataques a la cadena de suministro dirigidos a autoridades de certificación de confianza.

{{< netrunner-insight >}}

Para analistas del SOC: priorice la monitorización de anomalías en la firma de código y el uso inesperado de certificados. Los equipos de DevSecOps deben aplicar una gestión estricta del ciclo de vida de los certificados y considerar certificados de corta duración para limitar la exposición por robo.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
