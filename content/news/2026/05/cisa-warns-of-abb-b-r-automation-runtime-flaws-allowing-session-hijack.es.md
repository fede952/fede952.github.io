---
title: "CISA advierte sobre fallos en ABB B&R Automation Runtime que permiten secuestro de sesión"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiples vulnerabilidades en ABB B&R Automation Runtime anteriores a la versión 6.4 podrían permitir a atacantes secuestrar sesiones o ejecutar código. El aviso ICSA-26-141-04 de CISA detalla las correcciones."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiples vulnerabilidades en ABB B&R Automation Runtime anteriores a la versión 6.4 podrían permitir a atacantes secuestrar sesiones o ejecutar código. El aviso ICSA-26-141-04 de CISA detalla las correcciones.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA ha publicado el aviso ICSA-26-141-04 que detalla múltiples vulnerabilidades en ABB B&R Automation Runtime, una plataforma de software utilizada en automatización industrial. Las fallas, identificadas por el análisis de seguridad interno de B&R, afectan a versiones anteriores a la 6.4 e incluyen CVE-2025-3449 (identificadores de sesión predecibles), CVE-2025-3448 (cross-site scripting) y CVE-2025-11498 (neutralización incorrecta de elementos de fórmula en archivos CSV). Un atacante no autenticado podría explotarlas para secuestrar sesiones remotas o ejecutar código en el contexto del navegador de un usuario.

{{< ad-banner >}}

La vulnerabilidad más grave, CVE-2025-3449, reside en el componente System Diagnostic Manager (SDM) y tiene una puntuación CVSS v3 de 6.1. Permite a un atacante no autenticado basado en red tomar el control de sesiones ya establecidas debido a la generación de números o identificadores predecibles. El SDM está deshabilitado por defecto en Automation Runtime 6, lo que reduce la exposición, pero las organizaciones deben verificar que permanezca apagado a menos que sea explícitamente necesario.

ABB ha lanzado la versión 6.4 de Automation Runtime para solucionar estos problemas. Dado el despliegue del producto en el sector energético a nivel mundial, CISA insta a los operadores a aplicar la actualización de inmediato. El aviso señala que una explotación exitosa podría llevar a la ejecución remota de código o al secuestro de sesión, lo que representa un riesgo significativo para los entornos de control industrial.

{{< netrunner-insight >}}

Para analistas de SOC: priorice la aplicación de parches en instancias de Automation Runtime, especialmente aquellas con SDM habilitado. La falla de ID de sesión predecible (CVE-2025-3449) es trivialmente explotable a través de la red. Los equipos de DevSecOps deben asegurarse de que SDM permanezca deshabilitado en producción y validar que ninguna instancia expuesta sea accesible desde redes no confiables. Monitoree la actividad anómala de sesiones como señal de detección.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
