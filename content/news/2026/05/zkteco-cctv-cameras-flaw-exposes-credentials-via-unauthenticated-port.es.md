---
title: "Fallo en cámaras CCTV ZKTeco expone credenciales a través de puerto no autenticado"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "es"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre CVE-2026-8598 en cámaras CCTV ZKTeco, que permite el robo de credenciales mediante un puerto no documentado. Parche disponible en firmware V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "Cámaras CCTV ZKTeco"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre CVE-2026-8598 en cámaras CCTV ZKTeco, que permite el robo de credenciales mediante un puerto no documentado. Parche disponible en firmware V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="Cámaras CCTV ZKTeco" cve="CVE-2026-8598" cvss="9.1" >}}

CISA ha publicado un aviso (ICSA-26-139-04) detallando una vulnerabilidad crítica de omisión de autenticación en cámaras CCTV ZKTeco. La falla, registrada como CVE-2026-8598, involucra un puerto de exportación de configuración no documentado que es accesible sin autenticación. La explotación exitosa podría llevar a la divulgación de información, incluida la captura de credenciales de cuenta de la cámara.

{{< ad-banner >}}

La vulnerabilidad afecta a las versiones de firmware de la solución ZKTeco SSC335-GC2063-Face-0b77 anteriores a V5.0.1.2.20260421. La puntuación base CVSS v3 es 9.1, lo que indica gravedad crítica. Los dispositivos afectados se implementan en todo el mundo en instalaciones comerciales, con el fabricante con sede en China.

ZKTeco ha lanzado una versión de firmware parcheada V5.0.1.2.20260421 para solucionar el problema. Se recomienda encarecidamente a los usuarios que actualicen de inmediato. La vulnerabilidad se clasifica bajo CWE-288 (Omisión de autenticación mediante una ruta o canal alternativo).

{{< netrunner-insight >}}

Este es un ejemplo clásico de una interfaz de depuración expuesta que se convierte en una puerta trasera. Los analistas del SOC deben escanear inmediatamente las cámaras ZKTeco en su red y verificar las versiones de firmware. Para DevSecOps, esto subraya la necesidad de deshabilitar o proteger con firewall los puertos no documentados en las compilaciones de firmware IoT. Trate cualquier cámara con firmware inferior a V5.0.1.2.20260421 como comprometida hasta que se demuestre lo contrario.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
