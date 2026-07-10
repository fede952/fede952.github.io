---
title: "Puerta trasera GigaWiper combina borrado de disco, ransomware falso y spyware"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "es"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft descubre GigaWiper, una puerta trasera modular de Windows que incluye tres herramientas destructivas: borrador de disco, ransomware falso y spyware, representando una grave amenaza para los endpoints."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Endpoints Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft descubre GigaWiper, una puerta trasera modular de Windows que incluye tres herramientas destructivas: borrador de disco, ransomware falso y spyware, representando una grave amenaza para los endpoints.

{{< cyber-report severity="High" source="The Hacker News" target="Endpoints Windows" >}}

Microsoft ha identificado una nueva puerta trasera destructiva de Windows llamada GigaWiper, que integra tres programas maliciosos antiguos en un único marco modular. La puerta trasera ofrece a los operadores un menú de comandos para elegir, cada uno diseñado para infligir un tipo diferente de daño: borrado completo del disco, sobrescritura de la unidad del sistema de Windows o ejecución de ransomware falso que cifra archivos con una clave que nunca se guarda.

{{< ad-banner >}}

El diseño modular de GigaWiper permite a los atacantes adaptar sus acciones destructivas según el entorno objetivo. La inclusión de capacidades de borrado de disco y ransomware falso sugiere que el objetivo principal es causar la máxima interrupción y pérdida de datos, en lugar de obtener beneficios económicos. Esta combinación de técnicas convierte a GigaWiper en una herramienta versátil y peligrosa para operaciones cibernéticas destructivas.

Si bien el vector de distribución específico no se ha revelado, la capacidad de la puerta trasera para borrar discos enteros y simular ataques de ransomware indica un alto nivel de sofisticación. Las organizaciones deben priorizar soluciones de detección y respuesta en endpoints (EDR) y garantizar estrategias de respaldo sólidas para mitigar el impacto de tales amenazas.

{{< netrunner-insight >}}

Para los analistas del SOC, GigaWiper subraya la necesidad de reglas de detección conductual que señalen operaciones masivas de archivos y escrituras a nivel de disco. Los equipos de DevSecOps deben validar la integridad de las copias de seguridad y probar los procedimientos de recuperación regularmente, ya que el ransomware falso puede eludir los enfoques de descifrado tradicionales. Trate cualquier incidente de ransomware no verificado como un posible ataque de borrador hasta que se demuestre lo contrario.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
