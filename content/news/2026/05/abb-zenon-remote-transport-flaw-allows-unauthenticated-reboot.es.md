---
title: "Fallo en el Transporte Remoto de ABB Zenon permite reinicio no autorizado"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "es"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre CVE-2025-8754 en ABB Ability Zenon, que permite reinicios no autorizados del sistema a través del Servicio de Transporte Remoto. No se ha reportado explotación activa."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "sistemas ABB Ability Zenon"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre CVE-2025-8754 en ABB Ability Zenon, que permite reinicios no autorizados del sistema a través del Servicio de Transporte Remoto. No se ha reportado explotación activa.

{{< cyber-report severity="High" source="CISA" target="sistemas ABB Ability Zenon" cve="CVE-2025-8754" cvss="7.5" >}}

CISA ha publicado un aviso (ICSA-26-146-03) que detalla una vulnerabilidad de autenticación faltante en el Servicio de Transporte Remoto de ABB Ability Zenon. La falla, registrada como CVE-2025-8754 con una puntuación CVSS de 7.5, permite a un atacante provocar un reinicio del sistema sin credenciales adecuadas. Las versiones afectadas van desde la 7.50 hasta la 14.

{{< ad-banner >}}

La explotación requiere acceso previo a la red, ya que el atacante debe estar en la misma red que el sistema Zenon objetivo. ABB señala que en configuraciones predeterminadas, el servicio zensyssrv.exe se inicia automáticamente, pero los usuarios deben configurar una contraseña para usar el Servicio de Transporte Remoto. Al momento de redactar este informe, no hay evidencia de explotación activa en el entorno.

El aviso destaca la amplia implementación de ABB Ability Zenon en sectores de infraestructura crítica, incluidos los sistemas químicos, energéticos, sanitarios y de agua y aguas residuales en todo el mundo. Las organizaciones que utilizan versiones afectadas deben aplicar inmediatamente las mitigaciones o actualizaciones proporcionadas por ABB para prevenir posibles ataques de denegación de servicio.

{{< netrunner-insight >}}

Para los analistas del SOC: priorice la segmentación de la red para limitar la exposición de los sistemas Zenon y asegúrese de que las contraseñas del Servicio de Transporte Remoto estén configuradas y sean seguras. Los equipos de DevSecOps deben verificar que el servicio zensyssrv.exe no esté expuesto a redes no confiables y aplicar los parches del proveedor tan pronto como estén disponibles. Dado el CVSS 7.5 y el impacto en infraestructura crítica, trate esto como un hallazgo de alta prioridad incluso sin explotación activa.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
