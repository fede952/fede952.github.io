---
title: "Fallos críticos en el cargador EV XCharge C6 permiten ejecución remota de código"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "es"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre vulnerabilidades no autenticadas en controladores de carga EV XCharge C6, incluido CVE-2026-9037, con una puntuación CVSS de 9.8."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "Controladores de carga EV XCharge C6"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre vulnerabilidades no autenticadas en controladores de carga EV XCharge C6, incluido CVE-2026-9037, con una puntuación CVSS de 9.8.

{{< cyber-report severity="Critical" source="CISA" target="Controladores de carga EV XCharge C6" cve="CVE-2026-9037" cvss="9.8" >}}

CISA ha publicado un aviso (ICSA-26-148-08) que detalla múltiples vulnerabilidades críticas en los controladores de carga de vehículos eléctricos XCharge C6. Los fallos incluyen una descarga de código sin verificación de integridad (CWE-494), desbordamiento de búfer basado en pila e inicialización de un recurso con un valor predeterminado inseguro. La explotación exitosa podría permitir a un atacante obtener derechos de administrador o ejecutar código arbitrario en el dispositivo.

{{< ad-banner >}}

La vulnerabilidad más grave, CVE-2026-9037, implica un mecanismo de actualización de firmware que no valida la autenticidad de los paquetes de firmware. Sin verificación de firma criptográfica, un atacante que pueda interferir o suplantar el canal de gestión podría instalar firmware no autorizado, lo que llevaría a la ejecución de código con altos privilegios. La puntuación CVSS v3 para esta vulnerabilidad es 9.8, lo que indica gravedad crítica.

XCharge ha implementado una actualización de firmware para todos los cargadores afectados a partir del 22 de mayo de 2026. Se recomienda a los usuarios asegurarse de que sus dispositivos estén actualizados y contactar al soporte de XCharge si es necesario. El producto afectado se implementa ampliamente en el sector de sistemas de transporte en múltiples países.

{{< netrunner-insight >}}

Para los analistas del SOC, prioricen la monitorización de las interfaces de gestión de los cargadores XCharge C6 en busca de accesos no autorizados o solicitudes anómalas de actualización de firmware. Los equipos de DevSecOps deben aplicar la segmentación de red y aplicar el parche del proveedor de inmediato, ya que la falta de controles de integridad convierte a estos dispositivos en un objetivo principal para ataques a la cadena de suministro.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
