---
title: "Afiliado de Akira Ransomware Evade EDR mediante Modo Seguro y Exfiltra Datos"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "es"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "Un afiliado de Akira ransomware desactiva EDR arrancando en Modo Seguro con Red, roba datos pero falla en el cifrado. Aprenda a defenderse."
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "Soluciones de Detección y Respuesta de Endpoints (EDR)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un afiliado de Akira ransomware desactiva EDR arrancando en Modo Seguro con Red, roba datos pero falla en el cifrado. Aprenda a defenderse.

{{< cyber-report severity="High" source="BleepingComputer" target="Soluciones de Detección y Respuesta de Endpoints (EDR)" >}}

Se ha observado a un afiliado de Akira ransomware deshabilitando soluciones de detección y respuesta de endpoints (EDR) en sistemas comprometidos reiniciando la máquina en Modo Seguro con Red. Esta técnica permite al atacante operar sin monitoreo de EDR, ya que muchas herramientas de seguridad no se cargan en Modo Seguro.

{{< ad-banner >}}

El afiliado exfiltró con éxito datos sensibles de la red de la víctima, pero la fase de cifrado del ataque falló. Esto sugiere que, aunque la evasión de EDR fue efectiva, otros controles de seguridad o problemas operativos impidieron que la carga útil final del ransomware se ejecutara correctamente.

Este incidente resalta la importancia de endurecer las configuraciones de arranque y monitorear reinicios inesperados del sistema, especialmente en Modo Seguro. Las organizaciones también deben asegurarse de que las soluciones EDR tengan protección contra manipulaciones habilitada y que el arranque en Modo Seguro esté restringido o monitoreado.

{{< netrunner-insight >}}

Para los analistas del SOC, esto es un recordatorio de que las evasiones de EDR pueden ser tan simples como un reinicio en Modo Seguro. Monitoree eventos inusuales de apagado/reinicio y considere deshabilitar el arranque en Modo Seguro mediante contraseñas de BIOS/UEFI o políticas de grupo. DevSecOps debe asegurarse de que los agentes EDR estén configurados para iniciarse en Modo Seguro y que la protección contra manipulaciones esté aplicada para prevenir esta técnica de evasión común.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
