---
title: "MiniPlasma Windows 0-Day permite escalada de privilegios a SYSTEM en sistemas completamente parcheados"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "es"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "El investigador de seguridad Chaotic Eclipse publica un PoC para MiniPlasma, un día cero en el controlador Mini Filter de Windows Cloud Files (cldflt.sys) que otorga privilegios SYSTEM en sistemas completamente parcheados."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Controlador Mini Filter de Windows Cloud Files (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El investigador de seguridad Chaotic Eclipse publica un PoC para MiniPlasma, un día cero en el controlador Mini Filter de Windows Cloud Files (cldflt.sys) que otorga privilegios SYSTEM en sistemas completamente parcheados.

{{< cyber-report severity="High" source="The Hacker News" target="Controlador Mini Filter de Windows Cloud Files (cldflt.sys)" >}}

Chaotic Eclipse, el investigador de seguridad detrás de las fallas de Windows recientemente divulgadas YellowKey y GreenPlasma, ha publicado una prueba de concepto (PoC) para una falla de escalada de privilegios de día cero en Windows que otorga a los atacantes privilegios SYSTEM en sistemas Windows completamente parcheados. Con el nombre en clave MiniPlasma, la vulnerabilidad afecta a "cldflt.sys", que se refiere al controlador Mini Filter de Windows Cloud Files.

{{< ad-banner >}}

La falla permite que un atacante con acceso de usuario limitado escale privilegios a SYSTEM, lo que potencialmente permite el compromiso total del sistema. Al ser un día cero, no hay un parche oficial disponible actualmente, dejando a los sistemas completamente parcheados vulnerables a la explotación si el PoC se utiliza como arma.

Las organizaciones deben monitorear comportamientos inusuales del controlador cldflt.sys y considerar medidas de endurecimiento adicionales, como restringir el acceso a la función Cloud Files o aplicar mitigaciones temporales hasta que se publique un parche.

{{< netrunner-insight >}}

Los analistas del SOC deben priorizar la monitorización de intentos de explotación dirigidos a cldflt.sys, ya que el PoC reduce la barrera para los atacantes. Los equipos de DevSecOps deben revisar el endurecimiento de sus imágenes de Windows y considerar deshabilitar el controlador Mini Filter de Cloud Files si no es necesario, mientras esperan una solución oficial de Microsoft.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
