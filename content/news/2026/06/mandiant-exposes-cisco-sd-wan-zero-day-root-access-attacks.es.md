---
title: "Mandiant expone ataques de acceso root en Cisco SD-WAN mediante vulnerabilidad de día cero"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "es"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "Nuevos detalles revelan cómo los atacantes explotaron CVE-2026-20245 en ataques de día cero para crear cuentas root fraudulentas en dispositivos Cisco Catalyst SD-WAN."
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Dispositivos Cisco Catalyst SD-WAN"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Nuevos detalles revelan cómo los atacantes explotaron CVE-2026-20245 en ataques de día cero para crear cuentas root fraudulentas en dispositivos Cisco Catalyst SD-WAN.

{{< cyber-report severity="High" source="BleepingComputer" target="Dispositivos Cisco Catalyst SD-WAN" cve="CVE-2026-20245" >}}

Mandiant ha revelado nuevos detalles técnicos sobre cómo actores de amenazas explotaron una vulnerabilidad de día cero en el software Cisco Catalyst SD-WAN, registrada como CVE-2026-20245, para obtener acceso root en dispositivos objetivo. Los ataques implicaron la creación de cuentas root fraudulentas, permitiendo acceso no autorizado persistente.

{{< ad-banner >}}

La vulnerabilidad, que fue parcheada por Cisco en un aviso reciente, se utilizó en ataques limitados y dirigidos. El análisis de Mandiant revela la cadena de explotación específica, enfatizando la importancia de aplicar las actualizaciones de seguridad de inmediato.

Se insta a las organizaciones que utilizan soluciones Cisco SD-WAN a auditar sus sistemas en busca de signos de compromiso, como cuentas no autorizadas o actividad inusual a nivel root. El incidente subraya la necesidad crítica de una gestión de parches sólida y monitoreo de la infraestructura de red.

{{< netrunner-insight >}}

Para los analistas del SOC, priorice la monitorización de eventos de creación de cuentas no autorizadas y escalada de privilegios en los dispositivos Cisco SD-WAN. Los equipos de DevSecOps deben asegurar el despliegue rápido de los parches de seguridad de Cisco y considerar segmentar las interfaces de gestión de SD-WAN para reducir la superficie de ataque.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
