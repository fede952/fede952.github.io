---
title: "Paquetes Durmientes en Ruby Gems y Módulos de Go Apuntan a Pipelines CI/CD"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "es"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes utilizan paquetes durmientes para entregar cargas maliciosas, robando credenciales, manipulando GitHub Actions y estableciendo persistencia SSH en ataques a la cadena de suministro de software."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "Pipelines CI/CD y cadenas de suministro de software"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes utilizan paquetes durmientes para entregar cargas maliciosas, robando credenciales, manipulando GitHub Actions y estableciendo persistencia SSH en ataques a la cadena de suministro de software.

{{< cyber-report severity="High" source="The Hacker News" target="Pipelines CI/CD y cadenas de suministro de software" >}}

Se ha observado una nueva campaña de ataque a la cadena de suministro de software que utiliza paquetes durmientes como conducto para posteriormente enviar cargas maliciosas que permiten el robo de credenciales, la manipulación de GitHub Actions y la persistencia SSH. La actividad se ha atribuido a la cuenta de GitHub "BufferZoneCorp", que ha publicado un conjunto de repositorios asociados con Ruby gems y módulos de Go maliciosos.

{{< ad-banner >}}

El ataque aprovecha paquetes que inicialmente parecen benignos y que luego reciben actualizaciones maliciosas, una técnica conocida como paquetes "durmientes" o "troyanizados". Una vez instalados en entornos CI/CD, las cargas maliciosas roban credenciales, modifican flujos de trabajo de GitHub Actions y establecen acceso SSH persistente, lo que representa una amenaza significativa para los pipelines de desarrollo.

Las organizaciones que utilizan Ruby gems o módulos de Go de fuentes no confiables deben auditar sus dependencias y monitorear la actividad sospechosa en los repositorios. La campaña destaca la creciente sofisticación de los ataques a la cadena de suministro dirigidos a la infraestructura de desarrollo.

{{< netrunner-insight >}}

Esta campaña subraya la necesidad de fijar estrictamente las dependencias y verificar la integridad en los pipelines CI/CD. Los analistas del SOC deben monitorear modificaciones anómalas en GitHub Actions y adiciones de claves SSH, mientras que los ingenieros de DevSecOps deben implementar acceso con privilegios mínimos y considerar el uso de entornos de compilación efímeros para limitar el radio de explosión.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
