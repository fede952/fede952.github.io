---
title: "La botnet Evooo1Bot convierte dispositivos perimetrales en proxies SOCKS5"
date: "2026-08-18T07:31:16Z"
original_date: "2026-08-17T09:29:55"
lang: "es"
translationKey: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
slug: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "La nueva botnet Linux Evooo1Bot, derivada de Mirai, explota fallos conocidos para convertir dispositivos perimetrales en proxies SOCKS5 para ataques sigilosos."
original_url: "https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html"
source: "The Hacker News"
severity: "High"
target: "Dispositivos perimetrales expuestos a Internet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

La nueva botnet Linux Evooo1Bot, derivada de Mirai, explota fallos conocidos para convertir dispositivos perimetrales en proxies SOCKS5 para ataques sigilosos.

{{< cyber-report severity="High" source="The Hacker News" target="Dispositivos perimetrales expuestos a Internet" >}}

Investigadores de ciberseguridad han identificado una familia de botnets Linux previamente no documentada llamada Evooo1Bot, que deriva su funcionalidad principal del código fuente de la botnet Mirai filtrado públicamente. El malware está diseñado para convertir dispositivos expuestos a Internet en proxies SOCKS5, lo que permite a los atacantes enrutar tráfico malicioso a través de dispositivos comprometidos.

{{< ad-banner >}}

Si bien Evooo1Bot reutiliza el motor DDoS de Mirai, extiende el marco original con capacidades adicionales, incluida la capacidad de explotar vulnerabilidades conocidas en dispositivos perimetrales. Esto permite que la botnet amplíe su alcance y mantenga la persistencia en sistemas comprometidos.

El descubrimiento resalta la evolución continua de las botnets basadas en Mirai, que siguen siendo una amenaza significativa debido a su capacidad para reclutar dispositivos IoT y perimetrales vulnerables en redes de proxy a gran escala. Se recomienda a las organizaciones parchear vulnerabilidades conocidas y monitorear tráfico proxy inusual.

{{< netrunner-insight >}}

Para los analistas de SOC, esta botnet subraya la importancia de monitorear el tráfico proxy saliente y detectar conexiones SOCKS5 inusuales. Los equipos de DevSecOps deben priorizar el parcheo de vulnerabilidades conocidas en dispositivos perimetrales y considerar la segmentación de red para limitar el impacto de dichas botnets. La reutilización del código de Mirai significa que las firmas de detección existentes pueden necesitar actualizarse para detectar esta nueva variante.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html)**
