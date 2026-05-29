---
title: "CISA advierte sobre vulnerabilidades en ABB EIBPORT que permiten acceso a datos y cambios de configuración"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "Los dispositivos ABB EIBPORT son vulnerables a cross-site scripting y robo de ID de sesión. Está disponible una actualización de firmware a la versión 3.9.2."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "dispositivos ABB EIBPORT"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Los dispositivos ABB EIBPORT son vulnerables a cross-site scripting y robo de ID de sesión. Está disponible una actualización de firmware a la versión 3.9.2.

{{< cyber-report severity="High" source="CISA" target="dispositivos ABB EIBPORT" cve="CVE-2021-22291" >}}

CISA ha publicado un aviso (ICSA-26-148-03) que detalla múltiples vulnerabilidades en dispositivos ABB EIBPORT, específicamente los modelos EIBPORT V3 KNX y EIBPORT V3 KNX GSM. Las vulnerabilidades, que incluyen una falla de cross-site scripting (XSS) (CWE-79) y un problema de robo de ID de sesión (CVE-2021-22291), podrían permitir a un atacante acceder a información sensible almacenada en el dispositivo y alterar su configuración.

{{< ad-banner >}}

Las versiones de firmware afectadas son las anteriores a 3.9.2. ABB ha lanzado una actualización de firmware para corregir estas vulnerabilidades reportadas de forma privada. Los productos se implementan en todo el mundo en sectores críticos de fabricación y tecnología de la información, con el fabricante con sede en Suiza.

Aunque no se proporciona una puntuación CVSS en el aviso, el impacto potencial en la integridad y confidencialidad del dispositivo justifica una aplicación rápida de parches. Las organizaciones que utilicen dispositivos ABB EIBPORT afectados deben aplicar la actualización de firmware lo antes posible para mitigar el riesgo de explotación.

{{< netrunner-insight >}}

Para los analistas del SOC, priorice el escaneo de dispositivos ABB EIBPORT que ejecuten firmware inferior a 3.9.2 y monitoree cambios de configuración anómalos o anomalías en las sesiones. Los equipos de DevSecOps deben integrar esta actualización de firmware en su canal de gestión de parches, especialmente dado el papel del dispositivo en la automatización de edificios y la infraestructura crítica.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
