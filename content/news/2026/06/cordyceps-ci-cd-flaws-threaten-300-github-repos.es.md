---
title: "Las fallas de CI/CD Cordyceps amenazan a más de 300 repositorios de GitHub"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "es"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nueva debilidad en los flujos de trabajo de CI/CD, denominada Cordyceps, permite a los atacantes secuestrar flujos de trabajo y comprometer las cadenas de suministro de código abierto en grandes organizaciones."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "flujos de trabajo de CI/CD en GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nueva debilidad en los flujos de trabajo de CI/CD, denominada Cordyceps, permite a los atacantes secuestrar flujos de trabajo y comprometer las cadenas de suministro de código abierto en grandes organizaciones.

{{< cyber-report severity="Critical" source="The Hacker News" target="flujos de trabajo de CI/CD en GitHub" >}}

Investigadores de ciberseguridad de Novee Security han identificado un patrón crítico explotable en los flujos de trabajo de CI/CD, denominado Cordyceps, que puede permitir a los atacantes secuestrar flujos de trabajo y comprometer las cadenas de suministro de código abierto. La falla afecta a más de 300 repositorios de GitHub pertenecientes a grandes organizaciones como Microsoft, Google y Apache.

{{< ad-banner >}}

El patrón Cordyceps permite el control total del repositorio por parte del atacante, lo que potencialmente conduce a cambios de código no autorizados, inserción de puertas traseras y ataques posteriores a la cadena de suministro. La vulnerabilidad se origina en configuraciones de flujo de trabajo inseguras que no logran aislar o validar adecuadamente las entradas.

Se insta a las organizaciones que utilizan GitHub Actions o plataformas de CI/CD similares a revisar sus definiciones de flujo de trabajo en busca del patrón Cordyceps e implementar permisos de mínimo privilegio, saneamiento de entradas y aislamiento del entorno para mitigar el riesgo.

{{< netrunner-insight >}}

Este es un vector de ataque de cadena de suministro clásico. Los analistas del SOC deben monitorear ejecuciones anómalas de flujos de trabajo y cambios inesperados en los repositorios. Los equipos de DevSecOps deben auditar inmediatamente las configuraciones de los pipelines de CI/CD, centrándose en el manejo de entradas no confiables y el alcance de los permisos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
