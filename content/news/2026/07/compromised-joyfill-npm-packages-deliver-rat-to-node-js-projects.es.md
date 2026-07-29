---
title: "Paquetes npm joyfill comprometidos distribuyen RAT a proyectos Node.js"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "es"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Las versiones beta de @joyfill/layouts y @joyfill/components contienen un implante JavaScript en tiempo de importación que resuelve código cifrado para implementar un troyano de acceso remoto."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Desarrolladores de Node.js que utilizan paquetes joyfill"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Las versiones beta de @joyfill/layouts y @joyfill/components contienen un implante JavaScript en tiempo de importación que resuelve código cifrado para implementar un troyano de acceso remoto.

{{< cyber-report severity="High" source="The Hacker News" target="Desarrolladores de Node.js que utilizan paquetes joyfill" >}}

Dos paquetes npm en el espacio de nombres @joyfill, @joyfill/layouts versión 0.1.2-2773.beta.0 y @joyfill/components versión 4.0.0-rc24-2773-beta.4, han sido comprometidos. Estas versiones beta contienen un implante JavaScript en tiempo de importación que resuelve código cifrado, entregando finalmente un troyano de acceso remoto (RAT) asociado con la familia de malware DEV#POPPER.

{{< ad-banner >}}

El código malicioso se ejecuta cuando los paquetes se importan a un proyecto Node.js, dando a los atacantes acceso remoto al sistema comprometido. El ataque resalta el riesgo continuo de ataques a la cadena de suministro dirigidos al ecosistema npm, particularmente a través de versiones beta o candidatas a lanzamiento que pueden recibir menos escrutinio.

Los desarrolladores que hayan utilizado estas versiones específicas deben rotar inmediatamente las credenciales, escanear en busca de indicadores de compromiso y revisar sus árboles de dependencias en busca de otros paquetes sospechosos. El registro npm probablemente ha eliminado las versiones maliciosas, pero las instalaciones existentes siguen siendo una amenaza.

{{< netrunner-insight >}}

Este incidente subraya la importancia de examinar los paquetes de prelanzamiento e implementar comprobaciones de integridad de dependencias. Los analistas del SOC deben monitorear conexiones salientes inusuales desde aplicaciones Node.js, mientras que los equipos de DevSecOps deben aplicar un fijado estricto de versiones y usar herramientas como npm audit o escáneres SCA para detectar paquetes maliciosos conocidos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
