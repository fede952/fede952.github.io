---
title: "Nuevo QuimaRAT basado en Java como MaaS ataca Windows, Linux y macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "es"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT, un RAT Java multiplataforma vendido como malware como servicio, amenaza sistemas Windows, Linux y macOS. Investigadores de LevelBlue detallan su modelo de suscripción y capacidades."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "sistemas Windows, Linux y macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT, un RAT Java multiplataforma vendido como malware como servicio, amenaza sistemas Windows, Linux y macOS. Investigadores de LevelBlue detallan su modelo de suscripción y capacidades.

{{< cyber-report severity="High" source="The Hacker News" target="sistemas Windows, Linux y macOS" >}}

Investigadores de ciberseguridad de LevelBlue han identificado un nuevo troyano de acceso remoto (RAT) basado en Java llamado QuimaRAT, capaz de atacar entornos Windows, Linux y macOS. El malware se comercializa bajo un modelo de malware como servicio (MaaS), con niveles de suscripción que van desde $150 por un mes hasta $1,200 por acceso de por vida, además de un nivel de $300.

{{< ad-banner >}}

La naturaleza multiplataforma de QuimaRAT, habilitada por Java, le permite comprometer diversos sistemas operativos, convirtiéndolo en una amenaza versátil para organizaciones con entornos heterogéneos. El modelo MaaS reduce la barrera de entrada para actores de amenazas menos hábiles, lo que potencialmente aumenta la frecuencia de los ataques.

Si bien los detalles técnicos específicos sobre las capacidades de QuimaRAT son limitados en el informe inicial, su arquitectura basada en Java sugiere que podría aprovechar técnicas comunes como keylogging, captura de pantalla y exfiltración de archivos. Las organizaciones deben monitorear procesos sospechosos de Java e implementar listas blancas de aplicaciones para mitigar el riesgo.

{{< netrunner-insight >}}

Para los analistas del SOC, la naturaleza multiplataforma de QuimaRAT significa que las reglas de detección deben cubrir endpoints Windows, Linux y macOS. Los equipos de DevSecOps deben revisar el uso del runtime de Java y considerar restringir la ejecución de aplicaciones Java sin firmar. Dado el modelo MaaS, espere que atacantes de baja sofisticación desplieguen este RAT, por lo que es crítico monitorear líneas base para conexiones de red y comportamientos de procesos inusuales.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
