---
title: "Lanzamientos maliciosos de LiteLLM en PyPI vinculados al hackeo de Trivy exponen a más de 2,100 organizaciones"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "es"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "Dos paquetes maliciosos de LiteLLM en PyPI robaron claves de nube, claves SSH y más. Los datos de CloudSEK sugieren que más de 2,100 organizaciones podrían estar expuestas."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "Usuarios de LiteLLM en PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Dos paquetes maliciosos de LiteLLM en PyPI robaron claves de nube, claves SSH y más. Los datos de CloudSEK sugieren que más de 2,100 organizaciones podrían estar expuestas.

{{< cyber-report severity="High" source="The Hacker News" target="Usuarios de LiteLLM en PyPI" >}}

Dos lanzamientos maliciosos de LiteLLM se publicaron en PyPI y estuvieron disponibles durante aproximadamente 40 minutos en marzo. Estos paquetes contenían código de robo de credenciales diseñado para recolectar una amplia gama de secretos, incluyendo claves de acceso a la nube, claves privadas SSH, tokens de Kubernetes y contraseñas de bases de datos de cualquier sistema que los instalara.

{{< ad-banner >}}

La firma de inteligencia de amenazas CloudSEK obtuvo un conjunto de datos construido a partir de aproximadamente 434,000 archivos que los atacantes capturaron. El análisis de este conjunto de datos sugiere que la exposición podría afectar a más de 2,100 organizaciones, destacando la escala potencial del compromiso.

El incidente está vinculado al hackeo anterior de Trivy, lo que indica un ataque coordinado a la cadena de suministro. Las organizaciones que instalaron LiteLLM desde PyPI durante la ventana afectada deben rotar inmediatamente todas las credenciales expuestas e investigar si hay signos de acceso no autorizado.

{{< netrunner-insight >}}

Este incidente subraya la necesidad crítica de vigilancia en la cadena de suministro de software. Los analistas del SOC deben monitorear cualquier instalación de las versiones maliciosas de LiteLLM y priorizar la rotación de credenciales para cualquier secreto potencialmente expuesto. Los equipos de DevSecOps deben imponer controles estrictos de integridad de paquetes y considerar el uso de espejos privados o archivos de bloqueo con hashes para mitigar tales riesgos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
