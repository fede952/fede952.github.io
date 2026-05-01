---
title: "CISA advierte sobre una falla de path traversal en ABB PCM600 que conduce a RCE"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "Las versiones 1.5 a 2.13 de ABB PCM600 son vulnerables a una falla de path traversal (CVE-2018-1002208) que podría permitir la ejecución de código arbitrario. Actualice a la versión 2.14."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Las versiones 1.5 a 2.13 de ABB PCM600 son vulnerables a una falla de path traversal (CVE-2018-1002208) que podría permitir la ejecución de código arbitrario. Actualice a la versión 2.14.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA ha publicado un aviso (ICSA-26-120-02) que detalla una vulnerabilidad en ABB PCM600, un gestor de IED de protección y control. La falla, identificada como CVE-2018-1002208, existe en la librería SharpZip.dll e implica una limitación incorrecta de un nombre de ruta a un directorio restringido (path traversal). Una explotación exitosa podría permitir a un atacante enviar mensajes especialmente diseñados al nodo del sistema, resultando en la ejecución de código arbitrario.

{{< ad-banner >}}

Las versiones de producto afectadas son PCM600 desde la 1.5 hasta la 2.13 inclusive. ABB ha lanzado la versión 2.14 para remediar el problema. Sin embargo, tenga en cuenta que los relés de protección RE_630 no son compatibles con PCM600 2.14, por lo que los usuarios de versiones anteriores con RE_630 deben confiar en las defensas a nivel de sistema según lo indicado en las Recomendaciones Generales de Seguridad de ABB.

El aviso destaca que el producto se implementa en todo el mundo en el sector de Fabricación Crítica. Aunque no se proporciona una puntuación CVSS en el aviso, el potencial de la vulnerabilidad para la ejecución de código justifica una aplicación rápida de parches cuando sea posible. Las organizaciones deben priorizar la actualización a PCM600 2.14 e implementar segmentación de red y controles de acceso para los sistemas que no puedan actualizarse de inmediato.

{{< netrunner-insight >}}

Esta vulnerabilidad de path traversal en ABB PCM600 es un recordatorio de que las dependencias heredadas como SharpZip.dll pueden introducir riesgos. Para los analistas del SOC, monitoree el tráfico de red anómalo hacia los nodos PCM600, especialmente mensajes diseñados que podrían indicar intentos de explotación. Los ingenieros de DevSecOps deben inventariar todas las instancias de PCM600 y planificar las actualizaciones a la versión 2.14, asegurando que la compatibilidad con los relés RE_630 se aborde mediante controles compensatorios.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
