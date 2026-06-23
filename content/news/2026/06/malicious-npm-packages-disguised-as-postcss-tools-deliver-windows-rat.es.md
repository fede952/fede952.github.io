---
title: "Paquetes npm maliciosos disfrazados de herramientas PostCSS distribuyen un RAT para Windows"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "es"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Se han encontrado tres paquetes npm maliciosos que se hacen pasar por herramientas PostCSS y que distribuyen un troyano de acceso remoto para Windows. Los investigadores instan a tener precaución al instalar paquetes npm."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "usuarios de npm, sistemas Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Se han encontrado tres paquetes npm maliciosos que se hacen pasar por herramientas PostCSS y que distribuyen un troyano de acceso remoto para Windows. Los investigadores instan a tener precaución al instalar paquetes npm.

{{< cyber-report severity="High" source="The Hacker News" target="usuarios de npm, sistemas Windows" >}}

Investigadores de ciberseguridad han identificado tres paquetes npm maliciosos—aes-decode-runner-pro, postcss-minify-selector y postcss-minify-selector-parser—diseñados para distribuir un troyano de acceso remoto (RAT) para Windows. Los paquetes fueron publicados durante el último mes por un usuario de npm y han acumulado un total de 1,016 descargas, lo que indica una distribución moderada pero preocupante.

{{< ad-banner >}}

Los paquetes se hacen pasar por herramientas legítimas de PostCSS, un popular postprocesador de CSS, para engañar a los desarrolladores y lograr que los instalen. Una vez instalados, el código malicioso ejecuta una carga útil que establece acceso remoto a la máquina Windows infectada, lo que potencialmente permite a los atacantes exfiltrar datos, instalar malware adicional o moverse lateralmente dentro de la red.

Este incidente resalta la amenaza continua de typosquatting y confusión de dependencias en el ecosistema npm. Se recomienda a los desarrolladores verificar cuidadosamente los nombres de los paquetes, revisar el código fuente antes de la instalación y utilizar herramientas de verificación de integridad de paquetes para mitigar estos riesgos.

{{< netrunner-insight >}}

Para los analistas de SOC e ingenieros de DevSecOps, esto es un recordatorio de aplicar controles estrictos de procedencia de paquetes y monitorear instalaciones anómalas de paquetes npm. Considere implementar escaneo automatizado de paquetes maliciosos conocidos y educar a los desarrolladores sobre los riesgos de confiar ciegamente en los nombres de los paquetes. El número relativamente bajo de descargas sugiere que esta campaña podría estar en una etapa temprana, por lo que se justifica una búsqueda proactiva de paquetes similares.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
