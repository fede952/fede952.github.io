---
title: "CISA advierte sobre una falla en el abrepuertas de ABB que permite eludir el acceso físico"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "El aviso ICSA-26-148-04 de CISA detalla una vulnerabilidad de omisión de autenticación (CVE-2025-7705) en el actuador de abrepuertas con cable ABB Busch-Welcome 2, que permite el acceso no autorizado a edificios."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "Actuador de abrepuertas con cable ABB Busch-Welcome 2"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El aviso ICSA-26-148-04 de CISA detalla una vulnerabilidad de omisión de autenticación (CVE-2025-7705) en el actuador de abrepuertas con cable ABB Busch-Welcome 2, que permite el acceso no autorizado a edificios.

{{< cyber-report severity="Medium" source="CISA" target="Actuador de abrepuertas con cable ABB Busch-Welcome 2" cve="CVE-2025-7705" cvss="6.8" >}}

CISA ha publicado el aviso ICSA-26-148-04 sobre una vulnerabilidad de omisión de autenticación en el actuador de abrepuertas con cable ABB Busch-Welcome 2, identificada como CVE-2025-7705. La falla se origina en un modo de compatibilidad habilitado por defecto, que permite a un atacante obtener acceso físico no autorizado a edificios donde está instalado el producto afectado. La vulnerabilidad afecta a todas las versiones del actuador de interruptor 4 DU y al actuador de interruptor, puerta/luz 4 DU.

{{< ad-banner >}}

La puntuación base CVSS v3 para esta vulnerabilidad es 6.8, lo que indica una gravedad media. ABB ha proporcionado pasos de remediación que implican cambiar el modo del interruptor en el producto y realizar un reinicio de energía para recalibrar el sistema. El producto se implementa en todo el mundo, principalmente en instalaciones comerciales, y el proveedor tiene su sede en Suiza.

Las organizaciones que utilizan los sistemas ABB Busch-Welcome afectados deben aplicar inmediatamente las mitigaciones recomendadas. Dadas las implicaciones de seguridad física, esta vulnerabilidad representa un riesgo significativo para el control de acceso a edificios. Los equipos de seguridad deben verificar que los pasos de recalibración se ejecuten correctamente y monitorear cualquier signo de explotación.

{{< netrunner-insight >}}

Esta vulnerabilidad es un claro recordatorio de que los dispositivos IoT y de automatización de edificios a menudo vienen con configuraciones inseguras por defecto. Los analistas de SOC deben priorizar el descubrimiento de activos para los sistemas ABB Busch-Welcome y asegurarse de que se aplique la recalibración manual. Los equipos de DevSecOps deben abogar por principios de diseño seguro, especialmente para dispositivos que controlan el acceso físico.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
