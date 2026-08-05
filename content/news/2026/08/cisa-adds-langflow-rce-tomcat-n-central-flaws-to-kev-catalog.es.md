---
title: "CISA añade fallos de Langflow RCE, Tomcat y N-central al catálogo KEV"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "es"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA señala tres vulnerabilidades explotadas activamente, incluida Langflow RCE (CVE-2026-9198) con CVSS 9.8, instando a parchear de inmediato."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA señala tres vulnerabilidades explotadas activamente, incluida Langflow RCE (CVE-2026-9198) con CVSS 9.8, instando a parchear de inmediato.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

La Agencia de Seguridad de Infraestructura y Ciberseguridad de EE. UU. (CISA) ha añadido tres vulnerabilidades a su catálogo de Vulnerabilidades Explotadas Conocidas (KEV), citando evidencia de explotación activa. Entre ellas se encuentra CVE-2026-9198, una falla crítica de inyección de código en Langflow que permite a atacantes no autenticados lograr ejecución remota de código completa. La vulnerabilidad tiene una puntuación CVSS de 9.8, lo que indica un riesgo severo.

{{< ad-banner >}}

Las otras dos fallas afectan a Apache Tomcat y N-central, aunque no se proporcionan detalles específicos en el resumen. El catálogo KEV de CISA es una lista priorizada de vulnerabilidades conocidas por ser explotadas, y las agencias federales están obligadas a remediarlas dentro de plazos específicos. Se insta a las organizaciones a revisar el catálogo y aplicar parches de inmediato.

La inclusión de estas vulnerabilidades subraya la importancia de una gestión de parches oportuna y de la inteligencia de amenazas. Los equipos de seguridad deben monitorear indicadores de compromiso relacionados con estos CVE y asegurarse de que sus activos no estén expuestos a vectores de ataque conocidos.

{{< netrunner-insight >}}

Para los analistas del SOC, prioricen el monitoreo de intentos de explotación contra Langflow, Tomcat y N-central, ya que ahora son objetivos activos confirmados. DevSecOps debe acelerar el parcheo, especialmente para instancias expuestas a Internet, y considerar implementar reglas de detección adicionales para actividad posterior a la explotación. Dada la puntuación CVSS crítica, traten CVE-2026-9198 como un riesgo de primer nivel y validen que no haya ocurrido acceso no autorizado.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
