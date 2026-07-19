---
title: "La falla de DDoS HollowByte infla la memoria del servidor OpenSSL con una carga útil de 11 bytes"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "es"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "Una vulnerabilidad denominada HollowByte permite a atacantes no autenticados provocar una denegación de servicio en servidores OpenSSL con una carga útil maliciosa de solo 11 bytes."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "servidores OpenSSL"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una vulnerabilidad denominada HollowByte permite a atacantes no autenticados provocar una denegación de servicio en servidores OpenSSL con una carga útil maliciosa de solo 11 bytes.

{{< cyber-report severity="High" source="BleepingComputer" target="servidores OpenSSL" >}}

Una vulnerabilidad recién descubierta, llamada HollowByte, permite a atacantes no autenticados causar una denegación de servicio (DoS) en servidores OpenSSL enviando una carga útil especialmente diseñada de solo 11 bytes. La falla explota ineficiencias en la asignación de memoria, lo que provoca que la memoria del servidor se infla y eventualmente agote los recursos disponibles.

{{< ad-banner >}}

El ataque no requiere autenticación y puede ejecutarse de forma remota, lo que lo convierte en una amenaza significativa para cualquier organización que dependa de OpenSSL para comunicaciones seguras. El tamaño mínimo de la carga útil permite a los atacantes amplificar su impacto con ancho de banda limitado, potencialmente abrumando a los servidores con un esfuerzo mínimo.

Aunque aún no se ha asignado un identificador CVE, la vulnerabilidad se ha divulgado al proyecto OpenSSL y se esperan parches. Mientras tanto, se recomienda a los administradores monitorear el uso de memoria e implementar limitación de velocidad o reglas de detección de intrusiones para mitigar una posible explotación.

{{< netrunner-insight >}}

Para los analistas del SOC, este es un vector de DoS clásico de bajo ancho de banda y alto impacto que puede eludir las defensas volumétricas tradicionales. Los equipos de DevSecOps deben priorizar la aplicación de parches una vez que estén disponibles y considerar la implementación de alertas de monitoreo de memoria para detectar un crecimiento anómalo. La carga útil de 11 bytes lo convierte en un candidato ideal para su inclusión en reglas de detección de amenazas.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
