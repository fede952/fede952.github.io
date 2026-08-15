---
title: "UAC-0145 vinculado a Sandworm utiliza entrevistas de trabajo falsas para distribuir VPN malicioso"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "es"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-UA advierte sobre actores de amenaza patrocinados por el estado ruso que atacan a trabajadores de TI ucranianos mediante entrevistas de trabajo falsas, entregando una VPN que puede ejecutar comandos."
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "Trabajadores de TI ucranianos"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-UA advierte sobre actores de amenaza patrocinados por el estado ruso que atacan a trabajadores de TI ucranianos mediante entrevistas de trabajo falsas, entregando una VPN que puede ejecutar comandos.

{{< cyber-report severity="High" source="The Hacker News" target="Trabajadores de TI ucranianos" >}}

CERT-UA ha revelado una nueva campaña de ingeniería social atribuida al clúster de amenazas UAC-0145, un subgrupo del grupo de estado-nación ruso Sandworm (APT44). La campaña ataca a trabajadores de TI en Ucrania haciéndose pasar por reclutadores y atrayendo a las víctimas a entrevistas de trabajo falsas.

{{< ad-banner >}}

Durante el proceso de entrevista, las víctimas son engañadas para que instalen una aplicación VPN que en realidad es malware capaz de ejecutar comandos arbitrarios en el sistema comprometido. Esta técnica aprovecha la confianza asociada con la contratación laboral para eludir las defensas del usuario.

La actividad subraya la amenaza cibernética continua de actores patrocinados por el estado ruso contra organizaciones ucranianas, particularmente aquellas en el sector de TI. La atribución de CERT-UA a UAC-0145 destaca la naturaleza sofisticada y persistente de estos ataques.

{{< netrunner-insight >}}

Esta campaña demuestra la efectividad de la ingeniería social para distribuir malware, incluso a profesionales de TI conscientes de la seguridad. Los analistas del SOC deben educar a los usuarios sobre este tipo de señuelos de reclutamiento y monitorear instalaciones de VPN inusuales o ejecución de comandos. Los equipos de DevSecOps deben aplicar listas de permitidos de aplicaciones y restringir la ejecución de binarios no firmados para mitigar tales amenazas.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
