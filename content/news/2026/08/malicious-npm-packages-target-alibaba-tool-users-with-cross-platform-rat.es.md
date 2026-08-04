---
title: "Paquetes npm maliciosos apuntan a usuarios de herramientas de Alibaba con RAT multiplataforma"
date: "2026-08-04T09:40:19Z"
original_date: "2026-08-03T18:43:53"
lang: "es"
translationKey: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
slug: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Investigadores descubren 18 paquetes npm maliciosos, incluido 'lib-mtop', que entregan un RAT multiplataforma a usuarios de herramientas de desarrollo de Alibaba en un ataque dirigido a la cadena de suministro."
original_url: "https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html"
source: "The Hacker News"
severity: "High"
target: "usuarios de herramientas de desarrollo de Alibaba"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Investigadores descubren 18 paquetes npm maliciosos, incluido 'lib-mtop', que entregan un RAT multiplataforma a usuarios de herramientas de desarrollo de Alibaba en un ataque dirigido a la cadena de suministro.

{{< cyber-report severity="High" source="The Hacker News" target="usuarios de herramientas de desarrollo de Alibaba" >}}

Investigadores de ciberseguridad han identificado un nuevo conjunto de 18 paquetes npm maliciosos diseñados para atacar a usuarios de herramientas de desarrollo de Alibaba. El ataque forma parte de una campaña sofisticada y dirigida contra la cadena de suministro de software que se centra específicamente en entornos de habla china, lo que indica un alto nivel de reconocimiento y localización.

{{< ad-banner >}}

Uno de los paquetes, 'lib-mtop', es un paquete sin ámbito que comparte el mismo nombre que un paquete privado de Alibaba, una técnica clásica de typosquatting. Esto sugiere que los atacantes intentan engañar a los desarrolladores que podrían instalar por error el paquete malicioso en lugar del legítimo, obteniendo así un punto de apoyo en sus entornos de desarrollo.

Los paquetes maliciosos entregan un troyano de acceso remoto (RAT) multiplataforma a las víctimas, que puede proporcionar a los atacantes control remoto sobre los sistemas comprometidos. La naturaleza multiplataforma del RAT indica que está diseñado para afectar una amplia gama de sistemas operativos, aumentando el impacto potencial del ataque.

{{< netrunner-insight >}}

Este ataque subraya la importancia de verificar la autenticidad de los paquetes, especialmente cuando se utilizan paquetes privados o internos. Los analistas del SOC y los ingenieros de DevSecOps deben implementar controles estrictos de procedencia de paquetes, como el uso de archivos de bloqueo y la verificación de la integridad de los paquetes, y monitorear conexiones de red inesperadas desde las máquinas de desarrollo. Además, considere usar un registro privado con listas de permitidos para prevenir ataques de typosquatting.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)**
