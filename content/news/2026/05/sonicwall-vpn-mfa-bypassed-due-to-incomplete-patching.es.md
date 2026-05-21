---
title: "Bypass de MFA en SonicWall VPN debido a parcheo incompleto"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "es"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Actores de amenazas fuerzan credenciales de VPN y evitan la autenticación multifactor en dispositivos SonicWall Gen6 SSL-VPN sin parchear, implementando herramientas de ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "Dispositivos SonicWall Gen6 SSL-VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Actores de amenazas fuerzan credenciales de VPN y evitan la autenticación multifactor en dispositivos SonicWall Gen6 SSL-VPN sin parchear, implementando herramientas de ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Dispositivos SonicWall Gen6 SSL-VPN" >}}

Se ha observado que actores de amenazas fuerzan credenciales de VPN y evitan la autenticación multifactor (MFA) en dispositivos SonicWall Gen6 SSL-VPN. Los ataques explotan un parcheo incompleto, permitiendo a los adversarios implementar herramientas comúnmente utilizadas en operaciones de ransomware.

{{< ad-banner >}}

La vulnerabilidad permite a los atacantes obtener acceso no autorizado a redes internas después de comprometer las credenciales de VPN. Una vez dentro, pueden moverse lateralmente e implementar cargas útiles de ransomware, lo que representa un riesgo significativo para las organizaciones que dependen de estos dispositivos para el acceso remoto.

SonicWall ha publicado parches para solucionar el problema, pero la aplicación incompleta de estas actualizaciones deja los sistemas expuestos. Se insta a las organizaciones a verificar que todos los parches recomendados estén completamente instalados y a monitorear signos de acceso no autorizado a la VPN.

{{< netrunner-insight >}}

Este incidente subraya la importancia crítica de una gestión exhaustiva de parches. Los analistas del SOC deben priorizar la verificación de que todos los dispositivos SonicWall Gen6 tengan el firmware más reciente y monitorear los registros de VPN en busca de patrones de autenticación anómalos. Los equipos de DevSecOps deberían considerar la implementación de capas adicionales de MFA y segmentación de red para mitigar dichos bypasses.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
