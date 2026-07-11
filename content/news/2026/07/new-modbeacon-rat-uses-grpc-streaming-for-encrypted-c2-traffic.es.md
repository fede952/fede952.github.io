---
title: "Nuevo RAT MODBEACON utiliza streaming gRPC para tráfico C2 cifrado"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "es"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "El grupo Silver Fox vinculado a China despliega el RAT MODBEACON basado en Rust mediante envenenamiento SEO, utilizando streaming gRPC para comunicación C2 cifrada."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Usuarios de Windows a través de instaladores falsificados"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El grupo Silver Fox vinculado a China despliega el RAT MODBEACON basado en Rust mediante envenenamiento SEO, utilizando streaming gRPC para comunicación C2 cifrada.

{{< cyber-report severity="High" source="The Hacker News" target="Usuarios de Windows a través de instaladores falsificados" >}}

El grupo de ciberdelincuencia Silver Fox, vinculado a China, ha sido atribuido a un nuevo troyano de acceso remoto (RAT) basado en Rust llamado MODBEACON. El malware utiliza streaming gRPC para tráfico cifrado de comando y control (C2), lo que dificulta su detección.

{{< ad-banner >}}

Según la empresa china de ciberseguridad QiAnXin, Silver Fox propaga MODBEACON a través de instaladores falsificados mediante técnicas de envenenamiento SEO. Aunque el grupo puede parecer una operación de baja sofisticación y alta actividad, sus verdaderas capacidades organizativas son más avanzadas.

El uso de streaming gRPC para comunicación C2 representa una técnica novedosa para malware, ya que aprovecha HTTP/2 y buffers de protocolo para mezclarse con el tráfico legítimo. Los equipos de seguridad deben monitorear el tráfico gRPC inusual e investigar sitios de descarga envenenados por SEO.

{{< netrunner-insight >}}

Los analistas del SOC deben agregar análisis de tráfico gRPC a sus pipelines de detección, ya que el uso de RPC de streaming por parte de MODBEACON puede evadir las firmas de red tradicionales. Los equipos de DevSecOps deben verificar la integridad de las descargas de software y considerar bloquear dominios conocidos de envenenamiento SEO. Este RAT subraya la necesidad de caza proactiva de amenazas contra malware basado en Rust.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
