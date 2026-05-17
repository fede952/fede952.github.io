---
title: "CISA advierte sobre una falla en Siemens Opcenter RDnL a través de ActiveMQ Artemis sin autenticación"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "es"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL se ve afectado por CVE-2026-27446, una vulnerabilidad de falta de autenticación en ActiveMQ Artemis que permite a atacantes adyacentes no autenticados inyectar o extraer mensajes."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL se ve afectado por CVE-2026-27446, una vulnerabilidad de falta de autenticación en ActiveMQ Artemis que permite a atacantes adyacentes no autenticados inyectar o extraer mensajes.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA ha publicado un aviso (ICSA-26-134-09) que detalla una vulnerabilidad de falta de autenticación para funciones críticas en Apache ActiveMQ Artemis, que afecta a Siemens Opcenter RDnL. La falla, registrada como CVE-2026-27446 con una puntuación CVSS v3 de 7.1, permite que un atacante no autenticado dentro de la red adyacente fuerce a un broker objetivo a establecer una conexión de federación Core saliente hacia un broker malicioso. Esto puede provocar la inyección de mensajes en cualquier cola o la extracción de mensajes desde cualquier cola a través del broker malicioso.

{{< ad-banner >}}

La vulnerabilidad afecta a todas las versiones de Siemens Opcenter RDnL. Si bien el impacto en la integridad se considera bajo debido a la falta de funcionalidad de actualización automática y la ausencia de información confidencial en los mensajes, el impacto en la disponibilidad y el potencial de manipulación de mensajes siguen siendo significativos. ActiveMQ Artemis ha publicado una corrección, y Siemens recomienda actualizar a la última versión de inmediato.

Dado el despliegue en el sector de fabricación crítica a nivel mundial, las organizaciones que utilizan Opcenter RDnL deben priorizar la aplicación de parches. El vector de ataque de red adyacente reduce la exposición inmediata, pero aún representa un riesgo en entornos segmentados. Los equipos azules deben monitorear conexiones de federación Core inusuales y actividad de brokers maliciosos.

{{< netrunner-insight >}}

Para los analistas del SOC, monitoreen conexiones de federación Core salientes inesperadas desde brokers de ActiveMQ Artemis, ya que este es el principal indicador de explotación. Los equipos de DevSecOps deben actualizar inmediatamente a la última versión de ActiveMQ Artemis y restringir el acceso al protocolo Core solo a redes de confianza. Esta falla subraya el riesgo de la falta de autenticación en componentes de middleware, incluso cuando el impacto inmediato parece bajo.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
