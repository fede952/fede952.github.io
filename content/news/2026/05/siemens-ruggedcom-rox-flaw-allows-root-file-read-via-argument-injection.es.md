---
title: "Vulnerabilidad en Siemens Ruggedcom ROX permite lectura de archivos raíz mediante inyección de argumentos"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "es"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre CVE-2025-40948 que afecta a múltiples dispositivos Ruggedcom ROX. Un atacante remoto autenticado puede leer archivos arbitrarios con privilegios de root. Actualice a la versión 2.17.1 o posterior."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Dispositivos Siemens Ruggedcom ROX"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre CVE-2025-40948 que afecta a múltiples dispositivos Ruggedcom ROX. Un atacante remoto autenticado puede leer archivos arbitrarios con privilegios de root. Actualice a la versión 2.17.1 o posterior.

{{< cyber-report severity="Medium" source="CISA" target="Dispositivos Siemens Ruggedcom ROX" cve="CVE-2025-40948" cvss="6.8" >}}

Los dispositivos de la serie Siemens Ruggedcom ROX se ven afectados por una vulnerabilidad de control de acceso inadecuado (CVE-2025-40948) que permite a un atacante remoto autenticado leer archivos arbitrarios con privilegios de root del sistema operativo subyacente. La falla se origina en una validación incorrecta de la entrada en la interfaz JSON-RPC del servidor web, lo que permite la inyección de argumentos.

{{< ad-banner >}}

Los siguientes productos son vulnerables: RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536 y RX5000, todos con versiones anteriores a la 2.17.1. Siemens ha publicado actualizaciones para solucionar el problema y recomienda aplicar parches de inmediato.

Con una puntuación CVSS v3 de 6.8, esta vulnerabilidad está clasificada como gravedad Media. El vector de ataque es basado en red, requiere privilegios bajos y no necesita interacción del usuario. Dado los sectores de infraestructura crítica (por ejemplo, fabricación crítica) donde estos dispositivos están desplegados, la explotación podría conducir a una divulgación significativa de información.

{{< netrunner-insight >}}

Para analistas del SOC: priorice la aplicación de parches en los dispositivos Ruggedcom ROX de su entorno, especialmente aquellos expuestos a redes no confiables. La naturaleza autenticada del exploit reduce el riesgo inmediato pero no lo elimina: los atacantes que comprometan una cuenta con pocos privilegios pueden escalar al acceso completo a archivos raíz. Los equipos de DevSecOps deben revisar el endurecimiento del endpoint JSON-RPC y considerar la segmentación de la red para limitar la exposición.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
