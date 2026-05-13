---
title: "Fallos en Subnet Solutions PowerSYSTEM Center permiten fuga de información e inyección CRLF"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "es"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte de múltiples vulnerabilidades en Subnet Solutions PowerSYSTEM Center, incluyendo divulgación de información e inyección CRLF, que afectan a versiones desde 2020 hasta 2026."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte de múltiples vulnerabilidades en Subnet Solutions PowerSYSTEM Center, incluyendo divulgación de información e inyección CRLF, que afectan a versiones desde 2020 hasta 2026.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA ha publicado un aviso (ICSA-26-132-02) detallando múltiples vulnerabilidades en Subnet Solutions PowerSYSTEM Center, una plataforma utilizada en los sectores de fabricación crítica y energía. Los fallos incluyen una autorización incorrecta (CVE-2026-26289) que permite a usuarios autenticados con permisos limitados exportar cuentas de dispositivos y exponer información sensible normalmente restringida a administradores. Además, las vulnerabilidades de inyección CRLF (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) podrían permitir a atacantes inyectar encabezados o respuestas maliciosas.

{{< ad-banner >}}

Las versiones afectadas abarcan PowerSYSTEM Center 2020 (5.8.x a 5.28.x), 2024 (6.0.x a 6.1.x) y 2026 (7.0.x). Las vulnerabilidades tienen una puntuación base CVSS v3 de 8.2, lo que indica una gravedad alta. Una explotación exitosa podría llevar a la divulgación de información y posible manipulación de sesiones o división de respuestas HTTP.

Dado el despliegue del producto en infraestructuras críticas en todo el mundo, las organizaciones deberían priorizar la aplicación de parches. Subnet Solutions probablemente ha publicado actualizaciones; se recomienda a los administradores consultar los avisos de seguridad del proveedor y aplicar los últimos parches. Hasta entonces, restrinja el acceso de red a PowerSYSTEM Center y monitoree actividades anómalas.

{{< netrunner-insight >}}

Para los analistas del SOC, monitoree los registros de autenticación en busca de exportaciones inusuales de cuentas de dispositivos; esto es una señal reveladora de la explotación de CVE-2026-26289. Los equipos de DevSecOps deben inventariar inmediatamente las versiones de PowerSYSTEM Center y aplicar parches, ya que los vectores de inyección CRLF (CVE-2026-35504 y otros) podrían encadenarse con otros ataques para comprometer la integridad de la sesión. Trate esto como una remediación de alta prioridad dado el puntaje CVSS 8.2 y la exposición en sectores críticos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
