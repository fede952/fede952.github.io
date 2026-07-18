---
title: "La vulnerabilidad HollowByte de OpenSSL congela la memoria con solicitudes TLS de 11 bytes"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "es"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "Un error de denegación de servicio en OpenSSL, denominado HollowByte, permite a los atacantes congelar la memoria del servidor mediante pequeñas solicitudes TLS. El Red Team de Okta lo reportó; la corrección se envió sin CVE."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "Servidores OpenSSL en sistemas glibc"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un error de denegación de servicio en OpenSSL, denominado HollowByte, permite a los atacantes congelar la memoria del servidor mediante pequeñas solicitudes TLS. El Red Team de Okta lo reportó; la corrección se envió sin CVE.

{{< cyber-report severity="High" source="The Hacker News" target="Servidores OpenSSL en sistemas glibc" >}}

Una vulnerabilidad de denegación de servicio recientemente divulgada en OpenSSL, denominada HollowByte por el Red Team de Okta, permite a un atacante agotar la memoria del servidor con solo 11 bytes de datos de handshake TLS. El fallo provoca que un servidor OpenSSL sin parche asigne hasta 131 KB de memoria para un mensaje que nunca llega, y en sistemas que usan glibc, esa memoria no se libera hasta que el proceso se reinicia.

{{< ad-banner >}}

OpenSSL envió la corrección en junio de 2026 sin asignar un identificador CVE, emitir un aviso ni notar el cambio en el registro de cambios. El Red Team de Okta, que descubrió y reportó el error, publicó los detalles después de que se lanzara la corrección. La vulnerabilidad afecta a servidores OpenSSL que se ejecutan en sistemas basados en glibc, lo que los hace susceptibles a ataques de agotamiento de memoria.

Si bien el ataque requiere solo un único ClientHello TLS de 11 bytes, el impacto puede ser grave en entornos donde los procesos OpenSSL son de larga duración y manejan muchas conexiones concurrentes. Las organizaciones que ejecutan OpenSSL en glibc deben priorizar la aplicación de la actualización de junio de 2026 para prevenir posibles condiciones de denegación de servicio.

{{< netrunner-insight >}}

Este es un vector clásico de agotamiento de recursos que elude la limitación de velocidad tradicional porque el tráfico malicioso parece handshakes TLS normales. Los analistas del SOC deben monitorear picos repentinos en el uso de memoria en servidores OpenSSL, y los equipos de DevSecOps deben verificar que la actualización de OpenSSL de junio de 2026 esté implementada, incluso sin un CVE. La falta de un CVE no reduce el riesgo operativo: trate esto como un parche de alta prioridad.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
