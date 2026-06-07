---
title: "El gusano Miasma ataca 73 repositorios de Microsoft en GitHub en un ataque a la cadena de suministro"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "es"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Los repositorios de GitHub de Microsoft en Azure, Azure-Samples, Microsoft y MicrosoftDocs fueron comprometidos por el gusano autorreplicante Miasma, afectando a 73 repositorios."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "Repositorios de GitHub de Microsoft"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Los repositorios de GitHub de Microsoft en Azure, Azure-Samples, Microsoft y MicrosoftDocs fueron comprometidos por el gusano autorreplicante Miasma, afectando a 73 repositorios.

{{< cyber-report severity="High" source="The Hacker News" target="Repositorios de GitHub de Microsoft" >}}

La campaña de ataque a la cadena de suministro con el gusano autorreplicante Miasma se ha expandido para atacar los repositorios de GitHub de Microsoft, comprometiendo 73 repositorios en cuatro organizaciones: Azure, Azure-Samples, Microsoft y MicrosoftDocs. El incidente fue reportado por OpenSourceMalware, lo que llevó a GitHub a deshabilitar el acceso a los repositorios afectados para contener la propagación.

{{< ad-banner >}}

Este ataque subraya la creciente amenaza del malware autorreplicante en las cadenas de suministro de software. Al comprometer repositorios de confianza, los atacantes pueden inyectar código malicioso en proyectos descendentes que dependen de estas fuentes, afectando potencialmente a una amplia gama de usuarios y organizaciones.

Si bien los detalles técnicos específicos del compromiso no se han revelado, el incidente destaca la necesidad de medidas de seguridad mejoradas en los pipelines de CI/CD y la gestión de repositorios. Las organizaciones deben revisar sus dependencias de los repositorios de GitHub de Microsoft y monitorear cualquier actividad anómala.

{{< netrunner-insight >}}

Para los analistas del SOC, prioricen la monitorización de commits o patrones de acceso inusuales en sus propias organizaciones de GitHub. Los equipos de DevSecOps deben aplicar reglas estrictas de protección de ramas, exigir commits firmados e implementar escaneo automatizado para malware autorreplicante en los pipelines de CI/CD. Este incidente es un claro recordatorio de que incluso grandes proveedores como Microsoft no son inmunes a los ataques a la cadena de suministro.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
