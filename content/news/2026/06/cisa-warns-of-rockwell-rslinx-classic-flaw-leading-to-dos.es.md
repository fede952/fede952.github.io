---
title: "CISA advierte sobre una falla en Rockwell RSLinx Classic que provoca DoS"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "El aviso de CISA destaca CVE-2020-13573, un desbordamiento de búfer basado en pila en Rockwell Automation RSLinx Classic ≤4.50.00, que conlleva riesgo de denegación de servicio y ejecución remota de código."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El aviso de CISA destaca CVE-2020-13573, un desbordamiento de búfer basado en pila en Rockwell Automation RSLinx Classic ≤4.50.00, que conlleva riesgo de denegación de servicio y ejecución remota de código.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA ha publicado un aviso (ICSA-26-167-02) sobre una vulnerabilidad en Rockwell Automation RSLinx Classic, un software de comunicación industrial ampliamente utilizado. La falla, identificada como CVE-2020-13573, es un desbordamiento de búfer basado en pila que puede ser explotado de forma remota para ejecutar código arbitrario o causar una denegación de servicio, dejando la aplicación sin respuesta e incapaz de recuperarse automáticamente.

{{< ad-banner >}}

Las versiones afectadas incluyen RSLinx Classic hasta la versión 4.50.00 inclusive. La vulnerabilidad tiene una puntuación CVSS v3 de 7.5, lo que indica una gravedad alta. Rockwell Automation recomienda actualizar a la versión 4.60.00 o posterior, o aplicar el parche BF31213 para los clientes que no puedan actualizar de inmediato. El aviso también hace referencia a CWE-125 (Lectura fuera de los límites) como la debilidad subyacente.

Dados los sectores de infraestructura crítica involucrados—Fabricación Crítica, Energía, Alimentación y Agricultura, y Agua y Aguas Residuales—y el despliegue global del producto, la aplicación oportuna de parches es esencial. Las organizaciones deben priorizar esta actualización para mitigar el riesgo de explotación, especialmente en entornos donde RSLinx Classic está expuesto a redes no confiables.

{{< netrunner-insight >}}

Para los analistas del SOC, monitoree bloqueos inusuales o falta de respuesta en los procesos de RSLinx Classic, ya que pueden indicar intentos de explotación. Los equipos de DevSecOps deben planificar inmediatamente la actualización a la versión 4.60.00 o aplicar el parche BF31213, y asegurarse de que las instancias de RSLinx no sean accesibles directamente desde Internet. Dada la puntuación CVSS y el potencial de ejecución remota de código, trate esto como un elemento de remediación de alta prioridad.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
