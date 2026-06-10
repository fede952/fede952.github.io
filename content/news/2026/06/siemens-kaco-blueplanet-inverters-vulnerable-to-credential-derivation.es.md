---
title: "Inversores Siemens KACO Blueplanet Vulnerables a Derivación de Credenciales"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "es"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiples vulnerabilidades en inversores KACO blueplanet permiten a atacantes derivar credenciales a partir de números de serie, obteniendo acceso no autorizado. Siemens recomienda actualizaciones."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Inversores Siemens KACO Blueplanet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiples vulnerabilidades en inversores KACO blueplanet permiten a atacantes derivar credenciales a partir de números de serie, obteniendo acceso no autorizado. Siemens recomienda actualizaciones.

{{< cyber-report severity="High" source="CISA" target="Inversores Siemens KACO Blueplanet" >}}

CISA ha publicado un aviso (ICSA-26-160-02) detallando múltiples vulnerabilidades en inversores Siemens KACO blueplanet. Estas fallas podrían permitir a un atacante derivar credenciales del número de serie de un dispositivo y usarlas indebidamente para obtener acceso no autorizado al inversor.

{{< ad-banner >}}

El aviso cubre una amplia gama de modelos afectados, incluyendo blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3 y muchos otros, con versiones listadas como all/* o versiones de firmware específicas por debajo de 6.1.4.9. KACO new energy GmbH ha lanzado actualizaciones para algunos productos y está preparando correcciones para otros, recomendando contramedidas donde aún no hay parches disponibles.

No se proporcionan identificadores CVE ni puntuaciones CVSS en el aviso. Las vulnerabilidades se consideran graves debido al potencial de explotación remota que lleva a acceso no autorizado al dispositivo, lo que podría afectar la infraestructura de energía solar.

{{< netrunner-insight >}}

Para analistas de SOC e ingenieros DevSecOps, este aviso subraya el riesgo de credenciales hardcodeadas o derivables en dispositivos IoT/OT. Inmediatamente inventaríe los inversores KACO afectados y aplique actualizaciones de firmware donde estén disponibles. Para unidades sin parche, implemente segmentación de red y monitoree intentos de acceso anómalos como mitigaciones provisionales.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
