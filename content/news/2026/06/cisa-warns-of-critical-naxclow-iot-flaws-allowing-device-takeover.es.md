---
title: "CISA advierte sobre fallos críticos en Naxclow IoT que permiten el control de dispositivos"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiples vulnerabilidades en la plataforma Naxclow IoT, incluida CVE-2026-42947, permiten el secuestro de dispositivos y la recolección de credenciales. Afecta a timbres inteligentes y hubs domésticos."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Dispositivos de la plataforma Naxclow IoT"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiples vulnerabilidades en la plataforma Naxclow IoT, incluida CVE-2026-42947, permiten el secuestro de dispositivos y la recolección de credenciales. Afecta a timbres inteligentes y hubs domésticos.

{{< cyber-report severity="Critical" source="CISA" target="Dispositivos de la plataforma Naxclow IoT" cve="CVE-2026-42947" cvss="9.8" >}}

CISA ha emitido un aviso (ICSA-26-162-02) detallando múltiples vulnerabilidades en la plataforma Naxclow IoT, que afectan a productos como Smart Doorbell X3, X Smart Home, V720 e ix cam. La falla más grave, CVE-2026-42947, tiene una puntuación CVSS de 9.8 e implica una omisión de autorización mediante una clave controlada por el usuario, lo que permite a un atacante reproducir una secuencia de confirmación y vinculación para reasignar silenciosamente un dispositivo a una cuenta arbitraria sin interacción del usuario.

{{< ad-banner >}}

Las debilidades adicionales incluyen la falta de comprobaciones de autorización, el uso de claves criptográficas codificadas, la generación de identificadores predecibles y la inserción de información sensible en archivos accesibles externamente. La explotación exitosa podría permitir la suplantación de dispositivos, la interceptación o manipulación de comunicaciones, la recolección masiva de credenciales y el acceso no autorizado a los sistemas afectados.

Las vulnerabilidades afectan a todas las versiones de los productos listados, y los dispositivos están desplegados en todo el mundo en instalaciones comerciales. Naxclow, con sede en China, aún no ha publicado parches. Las organizaciones que utilizan estos dispositivos deben implementar inmediatamente segmentación de red y monitoreo para detectar actividades anómalas de vinculación de dispositivos.

{{< netrunner-insight >}}

Esta es una pesadilla de IoT en la cadena de suministro: claves codificadas, IDs predecibles y un flujo de incorporación reproducible. Los equipos del SOC deben buscar reasignaciones inesperadas de dispositivos en los registros y considerar aislar los dispositivos Naxclow en una VLAN separada hasta que lleguen los parches. DevSecOps debe impulsar la identidad criptográfica del dispositivo y la autenticación mutua en la incorporación de IoT.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
