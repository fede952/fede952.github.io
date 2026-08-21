---
title: "Vulnerabilidad de escape de sandbox en isolated-vm permite ejecución remota de código en una popular biblioteca de JavaScript"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "es"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "Una falla crítica en isolated-vm permite que JavaScript en sandbox escape al host, habilitando una posible ejecución remota de código. Todas las versiones hasta la 7.0.0 están afectadas."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "biblioteca de sandbox de JavaScript isolated-vm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una falla crítica en isolated-vm permite que JavaScript en sandbox escape al host, habilitando una posible ejecución remota de código. Todas las versiones hasta la 7.0.0 están afectadas.

{{< cyber-report severity="Critical" source="The Hacker News" target="biblioteca de sandbox de JavaScript isolated-vm" >}}

Se ha divulgado una vulnerabilidad de seguridad crítica en isolated-vm, una biblioteca de sandbox de JavaScript de código abierto ampliamente utilizada con más de 2,900 estrellas en GitHub y 190 bifurcaciones. La falla, rastreada como GHSA-864f-rcv7-6rh4, permite a los atacantes escapar del entorno de sandbox y potencialmente ejecutar código arbitrario en el sistema host. Todas las versiones de la biblioteca hasta la 7.0.0 inclusive están afectadas.

{{< ad-banner >}}

La vulnerabilidad es particularmente preocupante porque isolated-vm está diseñado para proporcionar un límite seguro para ejecutar código JavaScript no confiable. Un escape exitoso del sandbox podría comprometer la aplicación host y la infraestructura subyacente. Aunque aún no se ha asignado un identificador CVE, el aviso destaca la necesidad de atención inmediata por parte de los desarrolladores que utilizan esta biblioteca.

Las organizaciones que dependen de isolated-vm deben monitorear los parches y considerar controles de mitigación, como restringir la ejecución de código no confiable o aplicar capas de aislamiento adicionales. La falta de un CVE en este momento no disminuye la gravedad, ya que los exploits de prueba de concepto pueden estar circulando ya en la comunidad de seguridad.

{{< netrunner-insight >}}

Este escape de sandbox es un recordatorio contundente de que incluso las herramientas de aislamiento diseñadas específicamente pueden tener fallas críticas. Los analistas de SOC deben inventariar cualquier aplicación que use isolated-vm y priorizar el parcheo una vez que esté disponible una corrección. Los equipos de DevSecOps también deben revisar sus estrategias de sandboxing y considerar la defensa en profundidad, como ejecutar sandboxes en contenedores o máquinas virtuales separados para limitar el radio de explosión.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
