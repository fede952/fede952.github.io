---
title: "Siete paquetes npm maliciosos atacan el ecosistema de Vite con C2 basado en blockchain"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "es"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx descubre la campaña ViteVenom que utiliza infraestructura C2 basada en blockchain para distribuir un RAT a través de siete paquetes npm maliciosos dirigidos a la herramienta frontend Vite."
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Ecosistema de la herramienta frontend Vite"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx descubre la campaña ViteVenom que utiliza infraestructura C2 basada en blockchain para distribuir un RAT a través de siete paquetes npm maliciosos dirigidos a la herramienta frontend Vite.

{{< cyber-report severity="High" source="The Hacker News" target="Ecosistema de la herramienta frontend Vite" >}}

Investigadores de ciberseguridad de Checkmarx han identificado un grupo de siete paquetes npm maliciosos que atacan el ecosistema de la herramienta frontend Vite como parte de un ataque a la cadena de suministro de software. La campaña, denominada ViteVenom, representa una expansión de la operación ChainVeil observada anteriormente, que utilizaba una infraestructura de comando y control (C2) basada en blockchain de cuatro niveles sin precedentes en la red Tron.

{{< ad-banner >}}

Los paquetes maliciosos están diseñados para entregar un troyano de acceso remoto (RAT) a los sistemas comprometidos, permitiendo a los atacantes exfiltrar datos y mantener acceso persistente. El uso de blockchain para las comunicaciones C2 hace que la detección y eliminación sean más difíciles, ya que la infraestructura es descentralizada y resistente a las técnicas tradicionales de sinkholing.

Las organizaciones que utilizan Vite en sus pipelines de desarrollo deben auditar inmediatamente sus dependencias para identificar los paquetes maliciosos e implementar controles estrictos de integridad de paquetes. Este incidente resalta la creciente sofisticación de los ataques a la cadena de suministro de software, donde los atacantes aprovechan herramientas de desarrollo legítimas y redes descentralizadas para evadir la detección.

{{< netrunner-insight >}}

Para los analistas del SOC, monitorear las conexiones salientes a nodos de blockchain y consultas DNS inusuales puede ayudar a detectar esta técnica C2. Los equipos de DevSecOps deben imponer la firma de paquetes y usar herramientas de escaneo de dependencias para bloquear paquetes maliciosos conocidos antes de que ingresen al pipeline de compilación.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
