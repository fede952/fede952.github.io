---
title: "Nueva vulnerabilidad wp2shell en el núcleo de WordPress permite a atacantes no autenticados ejecutar código"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "es"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "Una solicitud HTTP anónima puede ejecutar código en sitios WordPress. El fallo afecta al núcleo, por lo que incluso instalaciones limpias son explotables. Todos los sitios con versiones 6.9 y 7.0 estaban en riesgo hasta que se aplicó el parche."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "Núcleo de WordPress (versiones 6.9 y 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una solicitud HTTP anónima puede ejecutar código en sitios WordPress. El fallo afecta al núcleo, por lo que incluso instalaciones limpias son explotables. Todos los sitios con versiones 6.9 y 7.0 estaban en riesgo hasta que se aplicó el parche.

{{< cyber-report severity="Critical" source="The Hacker News" target="Núcleo de WordPress (versiones 6.9 y 7.0)" >}}

Se ha descubierto una vulnerabilidad crítica de ejecución remota de código no autenticada en el núcleo de WordPress, que afecta a las versiones 6.9 y 7.0. El fallo, denominado wp2shell, permite a un atacante ejecutar código arbitrario en un sitio objetivo enviando una solicitud HTTP especialmente diseñada. Cabe destacar que la vulnerabilidad existe en el software del núcleo, lo que significa que incluso una instalación nueva de WordPress sin plugins es explotable.

{{< ad-banner >}}

Se han publicado los detalles técnicos completos y una prueba de concepto funcional, junto con los identificadores CVE asignados a los dos fallos subyacentes. También se ha identificado una condición de caché de objetos persistente que puede complicar la explotación en ciertos entornos. Todos los sitios que ejecutan las versiones afectadas se consideraron en riesgo hasta que se aplicaron los parches.

Se insta a los administradores a actualizar inmediatamente a la última versión parcheada. Dada la facilidad de explotación y el uso generalizado de WordPress, esta vulnerabilidad representa una amenaza significativa para la seguridad web. Las organizaciones deben priorizar el parcheo y revisar las reglas de su firewall de aplicaciones web para detectar y bloquear intentos de explotación.

{{< netrunner-insight >}}

Este es un ejemplo clásico de por qué el software del núcleo debe endurecerse contra ataques no autenticados. Los analistas del SOC deben escanear inmediatamente las instancias de WordPress 6.9 y 7.0 y verificar el estado del parcheo. Los equipos de DevSecOps deben tratar esto como un recordatorio para implementar protección de aplicaciones en tiempo de ejecución (RASP) y monitorear solicitudes HTTP anómalas dirigidas a wp-admin o wp-includes.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
