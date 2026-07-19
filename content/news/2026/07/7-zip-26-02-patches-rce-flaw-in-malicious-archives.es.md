---
title: "7-Zip 26.02 corrige una vulnerabilidad de ejecución remota de código en archivos maliciosos"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "es"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip lanzó la versión 26.02 para corregir una vulnerabilidad de ejecución remota de código que puede activarse al abrir archivos comprimidos especialmente diseñados. Actualice inmediatamente."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "Usuarios de 7-Zip"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip lanzó la versión 26.02 para corregir una vulnerabilidad de ejecución remota de código que puede activarse al abrir archivos comprimidos especialmente diseñados. Actualice inmediatamente.

{{< cyber-report severity="High" source="BleepingComputer" target="Usuarios de 7-Zip" >}}

Se ha lanzado la versión 26.02 de 7-Zip para solucionar una vulnerabilidad de ejecución remota de código (RCE) que podría permitir a los atacantes ejecutar código arbitrario en el sistema de la víctima. La falla es explotable al convencer a los usuarios de que abran archivos comprimidos especialmente diseñados, como archivos que contienen cargas maliciosas.

{{< ad-banner >}}

La vulnerabilidad afecta a todas las versiones anteriores del popular archivador de archivos. Aunque no se ha divulgado un identificador CVE en el anuncio, la gravedad se considera alta debido al potencial de compromiso total del sistema. Se recomienda encarecidamente a los usuarios que actualicen a la última versión de inmediato.

Dado el uso generalizado de 7-Zip tanto en entornos empresariales como de consumo, este parche es crítico para reducir la superficie de ataque. Las organizaciones deben priorizar la implementación mediante mecanismos de actualización automatizados o instalación manual.

{{< netrunner-insight >}}

Los analistas del SOC deben monitorear la actividad inusual de archivos comprimidos y asegurarse de que 7-Zip esté actualizado en todos los endpoints. Los equipos de DevSecOps deben integrar esta actualización en sus procesos de gestión de parches y considerar bloquear versiones anteriores de 7-Zip para acceder a sistemas sensibles.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
