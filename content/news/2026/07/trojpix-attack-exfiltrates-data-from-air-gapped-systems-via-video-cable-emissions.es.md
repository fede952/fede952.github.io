---
title: "El ataque TrojPix extrae datos de sistemas aislados mediante emisiones de cables de video"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "es"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "Investigadores demuestran TrojPix, una técnica que filtra datos de computadoras aisladas modulando píxeles en pantalla para emitir débiles señales de radio desde los cables de video, requiriendo acceso previo de malware."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "Sistemas aislados"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Investigadores demuestran TrojPix, una técnica que filtra datos de computadoras aisladas modulando píxeles en pantalla para emitir débiles señales de radio desde los cables de video, requiriendo acceso previo de malware.

{{< cyber-report severity="Medium" source="The Hacker News" target="Sistemas aislados" >}}

Investigadores de la Universidad de Shandong han presentado TrojPix, un novedoso ataque que extrae datos de computadoras aisladas explotando las emisiones electromagnéticas de los cables de video. La técnica altera sutilmente los píxeles en pantalla de manera imperceptible para el ojo humano, haciendo que el cable de video irradie una débil señal de radio que puede ser capturada y decodificada por un receptor cercano.

{{< ad-banner >}}

TrojPix requiere la instalación previa de malware en el sistema objetivo para manipular los valores de los píxeles. Este enfoque logra tasas de transferencia de datos significativamente más altas en comparación con canales encubiertos anteriores para sistemas aislados, lo que lo convierte en una amenaza práctica para entornos de alta seguridad. El ataque resalta el desafío continuo de proteger los datos incluso en redes físicamente aisladas.

Si bien la técnica es sofisticada, su dependencia de malware preexistente limita su aplicabilidad. Las organizaciones deben centrarse en prevenir el compromiso inicial mediante una seguridad robusta en los puntos finales y monitorear emisiones electromagnéticas inusuales en áreas sensibles.

{{< netrunner-insight >}}

Para los analistas del SOC, TrojPix subraya que los sistemas aislados no son inmunes a la filtración de datos. Monitoree señales electromagnéticas anómalas cerca de estaciones de trabajo sensibles y aplique una seguridad física estricta. Los equipos de DevSecOps deberían considerar blindar los cables de video e implementar detección de anomalías a nivel de píxeles cuando sea factible.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
